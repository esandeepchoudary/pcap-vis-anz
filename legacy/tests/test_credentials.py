"""Unit tests for credential extraction logic used in analyze_pcap().

These tests verify the regex/base64 decoding patterns directly without
requiring a full PCAP file, since the extraction is inlined in the hot loop.
"""
import base64
import re
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from urllib.parse import parse_qs
from app import _ber_len, analyze_anomalies


# ── Helpers mirroring the extraction patterns in app.py ──────────────────────

def _extract_http_basic(payload_bytes):
    """Return (username, password) from HTTP Basic auth header, or None."""
    try:
        text = payload_bytes[:4000].decode("utf-8", errors="replace")
        m = re.search(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", text, re.IGNORECASE)
        if m:
            decoded = base64.b64decode(m.group(1) + "==").decode("utf-8", errors="replace")
            if ":" in decoded:
                u, p = decoded.split(":", 1)
                return u, p
    except Exception:
        pass
    return None


def _extract_http_form_post(payload_bytes):
    """Return (username, password) from HTTP POST form body, or None."""
    try:
        if not payload_bytes[:5].startswith(b"POST "):
            return None
        text = payload_bytes.decode("utf-8", errors="replace")
        sep_idx = text.find("\r\n\r\n")
        sep_sz = 4
        if sep_idx == -1:
            sep_idx = text.find("\n\n")
            sep_sz = 2
        if sep_idx == -1:
            return None
        body_str = text[sep_idx + sep_sz:]
        form = parse_qs(body_str, keep_blank_values=True)
        pw_val = next((form[k][0][:120] for k in ("password", "passwd", "pwd") if k in form), None)
        if pw_val:
            user_val = next((form[k][0][:120] for k in ("username", "user", "login", "email", "name") if k in form), "")
            return user_val, pw_val
    except Exception:
        pass
    return None


def _extract_ftp(text, state):
    """Simulate FTP USER/PASS state machine. state is a dict modified in-place."""
    text = text.strip()
    if text.upper().startswith("USER "):
        state["user"] = text[5:].strip()
        return None
    elif text.upper().startswith("PASS ") and "user" in state:
        cred = (state.pop("user"), text[5:].strip())
        return cred
    return None


def _extract_smtp_auth_plain(text):
    """Return (username, password) from AUTH PLAIN base64 blob, or None."""
    m = re.match(r"AUTH PLAIN ([A-Za-z0-9+/=]+)", text.strip(), re.IGNORECASE)
    if m:
        try:
            decoded = base64.b64decode(m.group(1) + "==").decode("utf-8", errors="replace")
            parts = decoded.split("\x00")
            if len(parts) >= 3:
                return parts[1], parts[2]
        except Exception:
            pass
    return None


def _extract_pop3(text, state):
    """Simulate POP3 USER/PASS state machine."""
    text = text.strip()
    if text.upper().startswith("USER "):
        state["user"] = text[5:].strip()
        return None
    elif text.upper().startswith("PASS ") and "user" in state:
        return (state.pop("user"), text[5:].strip())
    return None


def _extract_imap_login(text):
    """Return (username, password) from IMAP LOGIN command, or None."""
    m = re.match(r'[A-Za-z0-9]+ LOGIN ("(?:[^"\\]|\\.)*"|[^\s"]+)\s+("(?:[^"\\]|\\.)*"|[^\s"]+)',
                 text.strip(), re.IGNORECASE)
    if m:
        return m.group(1).strip('"'), m.group(2).strip('"')
    return None


def _extract_ldap_simple_bind(payload):
    """Return (dn, password) from LDAP Simple Bind payload bytes, or None."""
    try:
        if len(payload) <= 6 or payload[0] != 0x30:
            return None
        off = 1
        _, off = _ber_len(payload, off)
        if off >= len(payload) or payload[off] != 0x02:
            return None
        off += 1
        mid_len, off = _ber_len(payload, off)
        off += mid_len
        if off >= len(payload) or payload[off] != 0x60:
            return None
        off += 1
        _, off = _ber_len(payload, off)
        if off < len(payload) and payload[off] == 0x02:
            off += 1
            vlen, off = _ber_len(payload, off)
            off += vlen
        dn = ""
        ldap_pw = ""
        if off < len(payload) and payload[off] == 0x04:
            off += 1
            dn_len, off = _ber_len(payload, off)
            dn = payload[off:off + dn_len].decode("utf-8", errors="replace")
            off += dn_len
        if off < len(payload) and payload[off] == 0x80:
            off += 1
            pw_len, off = _ber_len(payload, off)
            ldap_pw = payload[off:off + pw_len].decode("utf-8", errors="replace")
        if dn or ldap_pw:
            return dn, ldap_pw
    except Exception:
        pass
    return None


def _extract_snmp_community(payload):
    """Return community string from SNMP v1/v2c payload bytes, or None."""
    try:
        if len(payload) <= 6 or payload[0] != 0x30:
            return None
        off = 1
        _, off = _ber_len(payload, off)
        if off >= len(payload) or payload[off] != 0x02:
            return None
        off += 1
        vlen, off = _ber_len(payload, off)
        snmp_ver = payload[off] if vlen >= 1 else 99
        off += vlen
        if snmp_ver == 3:
            return None
        if off >= len(payload) or payload[off] != 0x04:
            return None
        off += 1
        clen, off = _ber_len(payload, off)
        if clen == 0 or clen > 120:
            return None
        return payload[off:off + clen].decode("utf-8", errors="replace")
    except Exception:
        pass
    return None


def _strip_iac(raw_bytes):
    """Strip Telnet IAC negotiation bytes, return cleaned text."""
    clean = bytearray()
    i = 0
    while i < len(raw_bytes):
        if raw_bytes[i] == 0xFF and i + 1 < len(raw_bytes):
            i += 1
            nb = raw_bytes[i]
            if nb == 0xFF:
                clean.append(0xFF)
                i += 1
            elif nb == 0xFA:
                i += 1
                while i + 1 < len(raw_bytes) and not (raw_bytes[i] == 0xFF and raw_bytes[i+1] == 0xF0):
                    i += 1
                i += 2
            elif 0xFB <= nb <= 0xFE:
                i += 2
            else:
                i += 1
        else:
            clean.append(raw_bytes[i])
            i += 1
    return clean.decode("utf-8", errors="replace")


def _build_ldap_simple_bind(dn_str, pw_str, version=3):
    """Build a minimal LDAP Simple Bind request as bytes."""
    dn = dn_str.encode()
    pw = pw_str.encode()
    ver_tlv = b"\x02\x01" + bytes([version])
    dn_tlv = b"\x04" + bytes([len(dn)]) + dn
    pw_tlv = b"\x80" + bytes([len(pw)]) + pw
    bind_inner = ver_tlv + dn_tlv + pw_tlv
    bind_req = b"\x60" + bytes([len(bind_inner)]) + bind_inner
    msg_id = b"\x02\x01\x01"
    msg_inner = msg_id + bind_req
    return b"\x30" + bytes([len(msg_inner)]) + msg_inner


def _build_snmp_get(community_str, version=0):
    """Build minimal SNMPv1/v2c GET request bytes."""
    community = community_str.encode()
    ver_tlv = b"\x02\x01" + bytes([version])
    comm_tlv = b"\x04" + bytes([len(community)]) + community
    # minimal PDU (GetRequest: tag 0xa0, empty varbinds)
    varbinds = b"\x30\x00"
    req_id = b"\x02\x01\x01"
    err = b"\x02\x01\x00"
    err_idx = b"\x02\x01\x00"
    pdu_inner = req_id + err + err_idx + varbinds
    pdu = b"\xa0" + bytes([len(pdu_inner)]) + pdu_inner
    msg_inner = ver_tlv + comm_tlv + pdu
    return b"\x30" + bytes([len(msg_inner)]) + msg_inner


# ── HTTP Basic auth ───────────────────────────────────────────────────────────

def test_http_basic_auth_extracted():
    token = base64.b64encode(b"admin:s3cr3t").decode()
    payload = f"GET /api HTTP/1.1\r\nAuthorization: Basic {token}\r\n\r\n".encode()
    result = _extract_http_basic(payload)
    assert result == ("admin", "s3cr3t")


def test_http_basic_auth_colon_in_password():
    token = base64.b64encode(b"user:pass:word").decode()
    payload = f"GET / HTTP/1.1\r\nAuthorization: Basic {token}\r\n\r\n".encode()
    u, p = _extract_http_basic(payload)
    assert u == "user"
    assert p == "pass:word"


def test_http_basic_auth_missing_returns_none():
    payload = b"GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"
    assert _extract_http_basic(payload) is None


def test_http_basic_auth_case_insensitive():
    token = base64.b64encode(b"root:toor").decode()
    payload = f"POST /login HTTP/1.1\r\nauthorization: basic {token}\r\n\r\n".encode()
    result = _extract_http_basic(payload)
    assert result == ("root", "toor")


# ── HTTP form POST ────────────────────────────────────────────────────────────

def test_http_form_post_password_extracted():
    payload = b"POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=alice&password=hunter2"
    result = _extract_http_form_post(payload)
    assert result is not None
    user, pw = result
    assert user == "alice"
    assert pw == "hunter2"


def test_http_form_post_passwd_variant():
    payload = b"POST /auth HTTP/1.1\r\n\r\nlogin=bob&passwd=secret123"
    user, pw = _extract_http_form_post(payload)
    assert pw == "secret123"


def test_http_form_post_no_password_returns_none():
    payload = b"POST /search HTTP/1.1\r\n\r\nquery=hello"
    assert _extract_http_form_post(payload) is None


def test_http_get_not_matched():
    payload = b"GET /page?username=x&password=y HTTP/1.1\r\n\r\n"
    assert _extract_http_form_post(payload) is None


def test_http_form_post_ampersand_in_password():
    # URL-encoded ampersand in password should be decoded correctly
    payload = b"POST /login HTTP/1.1\r\n\r\nusername=alice&password=pass%26word"
    user, pw = _extract_http_form_post(payload)
    assert pw == "pass&word"


# ── FTP ───────────────────────────────────────────────────────────────────────

def test_ftp_user_pass_sequence():
    state = {}
    assert _extract_ftp("USER ftpuser", state) is None
    assert state["user"] == "ftpuser"
    result = _extract_ftp("PASS ftppass", state)
    assert result == ("ftpuser", "ftppass")
    assert "user" not in state


def test_ftp_pass_without_user_ignored():
    state = {}
    assert _extract_ftp("PASS orphan", state) is None


def test_ftp_case_insensitive():
    state = {}
    _extract_ftp("user Admin", state)
    result = _extract_ftp("pass Secret!", state)
    assert result == ("Admin", "Secret!")


# ── SMTP AUTH PLAIN ───────────────────────────────────────────────────────────

def test_smtp_auth_plain_null_separated():
    blob = base64.b64encode(b"\x00user@example.com\x00mypassword").decode()
    result = _extract_smtp_auth_plain(f"AUTH PLAIN {blob}")
    assert result == ("user@example.com", "mypassword")


def test_smtp_auth_plain_not_matching_returns_none():
    assert _extract_smtp_auth_plain("EHLO mail.example.com") is None


def test_smtp_auth_plain_too_few_null_fields():
    blob = base64.b64encode(b"justonepart").decode()
    assert _extract_smtp_auth_plain(f"AUTH PLAIN {blob}") is None


# ── POP3 ─────────────────────────────────────────────────────────────────────

def test_pop3_user_pass_sequence():
    state = {}
    _extract_pop3("USER popuser", state)
    result = _extract_pop3("PASS poppassword", state)
    assert result == ("popuser", "poppassword")


def test_pop3_pass_without_user_ignored():
    state = {}
    assert _extract_pop3("PASS lonely", state) is None


# ── IMAP ─────────────────────────────────────────────────────────────────────

def test_imap_login_extracted():
    result = _extract_imap_login("a001 LOGIN imapuser secretpass")
    assert result == ("imapuser", "secretpass")


def test_imap_login_case_insensitive():
    result = _extract_imap_login("TAG1 login User Pass123")
    assert result is not None
    assert result[0] == "User"
    assert result[1] == "Pass123"


def test_imap_login_no_match():
    assert _extract_imap_login("a001 SELECT INBOX") is None


def test_imap_login_quoted_matched():
    result = _extract_imap_login('a001 LOGIN "user@example.com" "mypass"')
    assert result is not None
    assert result[0] == "user@example.com"
    assert result[1] == "mypass"


def test_imap_login_quoted_with_spaces():
    result = _extract_imap_login('a001 LOGIN "john doe" "my password"')
    assert result is not None
    assert result[0] == "john doe"
    assert result[1] == "my password"


# ── LDAP Simple Bind ─────────────────────────────────────────────────────────

def test_ldap_simple_bind_extracted():
    payload = _build_ldap_simple_bind("cn=admin,dc=example,dc=com", "ldappassword")
    result = _extract_ldap_simple_bind(payload)
    assert result is not None
    dn, pw = result
    assert dn == "cn=admin,dc=example,dc=com"
    assert pw == "ldappassword"


def test_ldap_anonymous_bind_skipped():
    payload = _build_ldap_simple_bind("", "")
    assert _extract_ldap_simple_bind(payload) is None


def test_ldap_non_sequence_skipped():
    assert _extract_ldap_simple_bind(b"\x04\x05hello") is None


def test_ldap_no_bind_request_skipped():
    # A valid SEQUENCE but no BindRequest (0x60) — e.g. a SearchRequest (0x63)
    msg_id = b"\x02\x01\x01"
    search = b"\x63\x05\x04\x03abc"
    inner = msg_id + search
    payload = b"\x30" + bytes([len(inner)]) + inner
    assert _extract_ldap_simple_bind(payload) is None


def test_ldap_dn_only_no_password():
    payload = _build_ldap_simple_bind("cn=user,dc=test,dc=com", "")
    result = _extract_ldap_simple_bind(payload)
    assert result is not None
    assert result[0] == "cn=user,dc=test,dc=com"
    assert result[1] == ""


# ── SNMP Community String ─────────────────────────────────────────────────────

def test_snmp_v1_community_extracted():
    payload = _build_snmp_get("public", version=0)
    result = _extract_snmp_community(payload)
    assert result == "public"


def test_snmp_v2c_community_extracted():
    payload = _build_snmp_get("private", version=1)
    result = _extract_snmp_community(payload)
    assert result == "private"


def test_snmp_v3_skipped():
    payload = _build_snmp_get("ignored", version=3)
    assert _extract_snmp_community(payload) is None


def test_snmp_empty_community_skipped():
    community = b""
    ver_tlv = b"\x02\x01\x00"
    comm_tlv = b"\x04\x00"
    inner = ver_tlv + comm_tlv
    payload = b"\x30" + bytes([len(inner)]) + inner
    assert _extract_snmp_community(payload) is None


def test_snmp_non_sequence_skipped():
    assert _extract_snmp_community(b"\x02\x01\x00") is None


# ── Telnet IAC stripping ──────────────────────────────────────────────────────

def test_telnet_iac_will_wont_stripped():
    # IAC WILL ECHO = FF FB 01
    raw = b"login:" + bytes([0xFF, 0xFB, 0x01]) + b" prompt"
    cleaned = _strip_iac(raw)
    assert "\xff" not in cleaned
    assert "login:" in cleaned
    assert "prompt" in cleaned


def test_telnet_iac_escaped_ff_preserved():
    # IAC IAC (FF FF) emits a literal 0xFF byte; decoded as UTF-8 it becomes the replacement char
    raw = bytes([0xFF, 0xFF]) + b"data"
    cleaned = _strip_iac(raw)
    assert len(cleaned) > 0
    assert "data" in cleaned


def test_telnet_iac_subnegotiation_stripped():
    # IAC SB ... IAC SE
    raw = b"before" + bytes([0xFF, 0xFA, 0x01, 0x02, 0xFF, 0xF0]) + b"after"
    cleaned = _strip_iac(raw)
    assert "before" in cleaned
    assert "after" in cleaned
    assert "\xff" not in cleaned


def test_telnet_plain_text_unchanged():
    raw = b"login: "
    assert _strip_iac(raw) == "login: "


# ── Deduplication ─────────────────────────────────────────────────────────────

def test_deduplication_same_session():
    """Same (proto, src, dst, dport, user, pw) → only one record should be stored."""
    cred_seen = set()
    credentials = []

    def _add_cred(protocol, src, dst, dport, username, password):
        rec = {"protocol": protocol, "src": src, "dst": dst,
               "dport": dport, "username": username, "password": password}
        key = (protocol, src, dst, dport, username, password)
        if key not in cred_seen:
            cred_seen.add(key)
            credentials.append(rec)

    _add_cred("FTP", "10.0.0.1", "10.0.0.2", 21, "alice", "secret")
    _add_cred("FTP", "10.0.0.1", "10.0.0.2", 21, "alice", "secret")
    _add_cred("FTP", "10.0.0.1", "10.0.0.2", 21, "alice", "secret")
    assert len(credentials) == 1


def test_deduplication_different_user():
    cred_seen = set()
    credentials = []

    def _add_cred(protocol, src, dst, dport, username, password):
        rec = {"protocol": protocol, "src": src, "dst": dst,
               "dport": dport, "username": username, "password": password}
        key = (protocol, src, dst, dport, username, password)
        if key not in cred_seen:
            cred_seen.add(key)
            credentials.append(rec)

    _add_cred("FTP", "10.0.0.1", "10.0.0.2", 21, "alice", "secret")
    _add_cred("FTP", "10.0.0.1", "10.0.0.2", 21, "bob", "secret")
    assert len(credentials) == 2


# ── Password reuse anomaly ────────────────────────────────────────────────────

def test_password_reuse_detected():
    creds = [
        {"protocol": "FTP",  "src": "10.0.0.1", "dst": "10.0.0.2",
         "dport": 21,  "username": "alice",           "password": "shared_pw"},
        {"protocol": "SMTP", "src": "10.0.0.1", "dst": "10.0.0.3",
         "dport": 25,  "username": "alice@example.com", "password": "shared_pw"},
    ]
    anomalies = analyze_anomalies({}, {}, {}, credentials=creds)
    types = [a["type"] for a in anomalies]
    assert "password_reuse" in types
    pw_reuse = next(a for a in anomalies if a["type"] == "password_reuse")
    assert pw_reuse["severity"] == "high"
    assert "2 services" in pw_reuse["description"]


def test_password_reuse_single_service_no_anomaly():
    creds = [
        {"protocol": "FTP", "src": "10.0.0.1", "dst": "10.0.0.2",
         "dport": 21, "username": "alice", "password": "unique_pw"},
    ]
    anomalies = analyze_anomalies({}, {}, {}, credentials=creds)
    types = [a["type"] for a in anomalies]
    assert "password_reuse" not in types


def test_password_reuse_short_password_ignored():
    # Passwords shorter than 4 chars are not flagged
    creds = [
        {"protocol": "FTP",  "src": "10.0.0.1", "dst": "10.0.0.2", "dport": 21,
         "username": "u1", "password": "ab"},
        {"protocol": "SMTP", "src": "10.0.0.1", "dst": "10.0.0.3", "dport": 25,
         "username": "u2", "password": "ab"},
    ]
    anomalies = analyze_anomalies({}, {}, {}, credentials=creds)
    types = [a["type"] for a in anomalies]
    assert "password_reuse" not in types


def test_password_reuse_no_credentials_no_error():
    anomalies = analyze_anomalies({}, {}, {}, credentials=None)
    types = [a["type"] for a in anomalies]
    assert "password_reuse" not in types


def test_password_reuse_empty_credentials_no_error():
    anomalies = analyze_anomalies({}, {}, {}, credentials=[])
    types = [a["type"] for a in anomalies]
    assert "password_reuse" not in types
