"""Cleartext credential extraction (consultants report these as findings)."""

import re
from dataclasses import dataclass, field

from pcapvis.engine.packet import Packet

USER_KEYS = re.compile(r"^(user(name)?|login|email|uname|usr|account|userid|user_id|j_username)$", re.I)
PASS_KEYS = re.compile(r"^(pass(word|wd)?|pwd|passphrase|secret|j_password|pin)$", re.I)
TELNET_USER_PROMPT = re.compile(r"(login|user(name)?)\s*:\s*$", re.I)
TELNET_PASS_PROMPT = re.compile(r"password\s*:\s*$", re.I)
MAX_CREDENTIALS = 2000


@dataclass
class CredentialHit:
    protocol: str
    kind: str  # "password" | "basic_auth" | "form" | "community" | "token"
    username: str | None
    secret: str | None


@dataclass
class _TelnetState:
    awaiting: str | None = None  # "user" | "pass"
    buf: str = ""
    user: str | None = None


@dataclass
class CredentialTracker:
    pending_user: dict[int, str] = field(default_factory=dict)  # flow id → username awaiting PASS
    telnet: dict[int, _TelnetState] = field(default_factory=dict)

    def extract(self, p: Packet, flow_id: int, c2s: bool) -> list[CredentialHit]:
        L = p.layers
        hits: list[CredentialHit] = []
        # FTP / POP3: USER then PASS on the same connection.
        for proto, cmd_key, arg_key in (
            ("FTP", "ftp_request_command", "ftp_request_arg"),
            ("POP3", "pop_request_command", "pop_request_parameter"),
        ):
            if cmd_key in L:
                cmd = L[cmd_key][0].upper()
                arg = (L.get(arg_key) or [""])[0]
                if cmd == "USER":
                    self.pending_user[flow_id] = arg
                elif cmd == "PASS":
                    hits.append(CredentialHit(proto, "password", self.pending_user.pop(flow_id, None), arg))
        if "imap_request_username" in L:
            hits.append(
                CredentialHit(
                    "IMAP",
                    "password",
                    L["imap_request_username"][0],
                    (L.get("imap_request_password") or [None])[0],
                )
            )
        if "smtp_auth_username" in L or "smtp_auth_password" in L:
            user = (L.get("smtp_auth_username") or [None])[0]
            pw = (L.get("smtp_auth_password") or [None])[0]
            if user:
                self.pending_user[flow_id] = user
            if pw:
                hits.append(CredentialHit("SMTP", "password", self.pending_user.pop(flow_id, user), pw))
        if "http_authbasic" in L:
            user, _, pw = L["http_authbasic"][0].partition(":")
            hits.append(CredentialHit("HTTP", "basic_auth", user, pw))
        elif "http_authorization" in L and L["http_authorization"][0].lower().startswith("bearer "):
            hits.append(CredentialHit("HTTP", "token", None, L["http_authorization"][0][7:]))
        if "urlencoded-form_key" in L:
            pairs = dict(zip(L["urlencoded-form_key"], L.get("urlencoded-form_value", []), strict=False))
            user = next((v for k, v in pairs.items() if USER_KEYS.match(k)), None)
            pw = next((v for k, v in pairs.items() if PASS_KEYS.match(k)), None)
            if pw is not None:
                hits.append(CredentialHit("HTTP", "form", user, pw))
        if "mqtt_username" in L or "mqtt_passwd" in L:
            hits.append(
                CredentialHit(
                    "MQTT",
                    "password",
                    (L.get("mqtt_username") or [None])[0],
                    (L.get("mqtt_passwd") or [None])[0],
                )
            )
        if "snmp_community" in L and c2s:
            hits.append(CredentialHit("SNMP", "community", None, L["snmp_community"][0]))
        if "telnet_data" in L:
            hits.extend(self._telnet(flow_id, c2s, "".join(L["telnet_data"])))
        return hits

    def _telnet(self, flow_id: int, c2s: bool, text: str) -> list[CredentialHit]:
        st = self.telnet.setdefault(flow_id, _TelnetState())
        hits = []
        if not c2s:  # server output: look for prompts
            tail = text.replace("\r", "").split("\n")[-1]
            if TELNET_PASS_PROMPT.search(tail):
                st.awaiting, st.buf = "pass", ""
            elif TELNET_USER_PROMPT.search(tail):
                st.awaiting, st.buf = "user", ""
            return hits
        if st.awaiting is None:
            return hits
        for ch in text:
            if ch in "\r\n\x00":
                if st.buf or st.awaiting == "pass":
                    if st.awaiting == "user":
                        st.user = st.buf
                    elif st.awaiting == "pass":
                        hits.append(CredentialHit("Telnet", "password", st.user, st.buf))
                        st.user = None
                    st.awaiting, st.buf = None, ""
                break
            if ch in "\x08\x7f":  # backspace
                st.buf = st.buf[:-1]
            elif ch.isprintable():
                st.buf += ch
        return hits
