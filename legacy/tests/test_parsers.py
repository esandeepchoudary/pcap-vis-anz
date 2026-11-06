"""Unit tests for OT/ICS protocol parsers in app.py."""
import struct
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import parse_modbus, parse_dnp3, parse_s7comm, parse_enip, parse_iec104, parse_bacnet, parse_tls_client_hello, _is_grease


# ── Modbus ────────────────────────────────────────────────────────────────────

def _modbus_pkt(transaction_id, unit_id, func_code, data=b""):
    length = 2 + len(data)  # unit_id + func_code + data
    hdr = struct.pack(">HHHBB", transaction_id, 0, length, unit_id, func_code)
    return hdr + data


def test_modbus_read_holding_registers():
    pkt = _modbus_pkt(1, 1, 3, struct.pack(">HH", 100, 10))
    r = parse_modbus(pkt)
    assert r is not None
    assert r["function_code"] == 3
    assert r["function_name"] == "Read Holding Registers"
    assert r["is_write"] is False
    assert r["is_error"] is False
    assert r["register_address"] == 100
    assert r["quantity"] == 10
    assert r["unit_id"] == 1
    assert r["unit_id_zero"] is False


def test_modbus_bulk_read_quantity():
    pkt = _modbus_pkt(1, 1, 3, struct.pack(">HH", 0, 125))
    r = parse_modbus(pkt)
    assert r["quantity"] == 125


def test_modbus_write_single_register():
    pkt = _modbus_pkt(2, 5, 6, struct.pack(">HH", 200, 42))
    r = parse_modbus(pkt)
    assert r["function_code"] == 6
    assert r["is_write"] is True
    assert r["register_address"] == 200


def test_modbus_exception_response():
    # FC 3 error = 0x83, exception code 2 = Illegal Data Address
    pkt = _modbus_pkt(3, 1, 0x83, bytes([2]))
    r = parse_modbus(pkt)
    assert r is not None
    assert r["is_error"] is True
    assert r["exception_code"] == 2
    assert r["exception_name"] == "Illegal Data Address"
    assert r["function_code"] == 3  # real FC = 0x83 & 0x7F


def test_modbus_broadcast_unit_id():
    pkt = _modbus_pkt(1, 0, 6, struct.pack(">HH", 0, 1))
    r = parse_modbus(pkt)
    assert r["unit_id_zero"] is True


def test_modbus_invalid_protocol_id():
    # Protocol ID must be 0; if not, should return None
    bad = struct.pack(">HHHBB", 1, 9999, 2, 1, 3)
    assert parse_modbus(bad) is None


def test_modbus_too_short():
    assert parse_modbus(b"\x00\x01") is None
    assert parse_modbus(None) is None


# ── DNP3 ─────────────────────────────────────────────────────────────────────

def _dnp3_pkt(direction_bit, dst, src, app_fc, group_byte=0):
    ctrl = (0x80 if direction_bit else 0x00) | 0x44  # PRM=1, FCB=1
    pkt = bytes([0x05, 0x64, 14, ctrl]) + \
          dst.to_bytes(2, "little") + src.to_bytes(2, "little") + \
          bytes([0xFF, 0xFF,  # CRC placeholder
                 0xC0, app_fc,  # app control + FC
                 group_byte, 0x01])  # object group + variation
    return pkt


def test_dnp3_master_role():
    pkt = _dnp3_pkt(direction_bit=1, dst=2, src=1, app_fc=1)
    r = parse_dnp3(pkt)
    assert r is not None
    assert r["role"] == "master"
    assert r["src_address"] == 1
    assert r["dst_address"] == 2
    assert r["function_code"] == 1


def test_dnp3_outstation_role():
    pkt = _dnp3_pkt(direction_bit=0, dst=1, src=2, app_fc=129)
    r = parse_dnp3(pkt)
    assert r["role"] == "outstation"


def test_dnp3_control_is_write():
    pkt = _dnp3_pkt(direction_bit=1, dst=2, src=1, app_fc=3)  # FC 3 = Select
    r = parse_dnp3(pkt)
    assert r["is_write"] is True


def test_dnp3_data_object_group_binary_output_control():
    pkt = _dnp3_pkt(direction_bit=1, dst=2, src=1, app_fc=5, group_byte=12)
    r = parse_dnp3(pkt)
    assert r["data_object_group"] == "Binary Output Control (CROB)"


def test_dnp3_invalid_start_bytes():
    assert parse_dnp3(b"\x06\x64" + b"\x00" * 10) is None
    assert parse_dnp3(None) is None


# ── S7comm ────────────────────────────────────────────────────────────────────

def _s7_pkt(rosctr, func_code, param_data=b""):
    # TPKT(4) + COTP(3) + S7 header(10) + param
    param_len = 1 + len(param_data)  # func_code byte + extra
    data_len = 0
    tpkt = bytes([0x03, 0x00, 0x00, 20 + len(param_data)])
    cotp = bytes([0x02, 0xF0, 0x80])
    s7hdr = bytes([0x32, rosctr, 0, 0, 0, 1, 0, param_len, 0, data_len])
    params = bytes([func_code]) + param_data
    return tpkt + cotp + s7hdr + params


def test_s7_read_variable():
    pkt = _s7_pkt(rosctr=1, func_code=0x04)
    r = parse_s7comm(pkt)
    assert r is not None
    assert r["function_code"] == 0x04
    assert r["function_name"] == "Read Variable"
    assert r["is_write"] is False


def test_s7_write_variable():
    pkt = _s7_pkt(rosctr=1, func_code=0x05)
    r = parse_s7comm(pkt)
    assert r["is_write"] is True


def test_s7_plc_stop():
    pkt = _s7_pkt(rosctr=1, func_code=0x29)
    r = parse_s7comm(pkt)
    assert r["function_code"] == 0x29
    assert r["is_write"] is True


def test_s7_invalid_tpkt():
    pkt = bytes([0x04, 0x00, 0x00, 20]) + b"\x00" * 20
    assert parse_s7comm(pkt) is None


def test_s7_too_short():
    assert parse_s7comm(b"\x03\x00") is None
    assert parse_s7comm(None) is None


def test_s7_ack_data_rosctr3():
    # ROSCTR=3 (Ack-Data) has a 12-byte S7 header: the two extra bytes at [10],[11]
    # are error_class / error_code.  Parameters (and func_code) start at offset 12.
    # Previously the code read s7[10] for ROSCTR in (1,3) which returned the
    # error_class byte instead of the function code, mis-decoding every S7 response.
    tpkt   = bytes([0x03, 0x00, 0x00, 0x00])   # length placeholder, not validated
    cotp   = bytes([0x02, 0xF0, 0x80])
    # 12-byte header: magic, rosctr=3, reserved*2, pdu_ref*2, param_len=1, _, data_len=0, _,
    #                 error_class=0, error_code=0
    s7hdr  = bytes([0x32, 3, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0])
    params = bytes([0x04])                      # func_code = Read Variable
    pkt    = tpkt + cotp + s7hdr + params
    r = parse_s7comm(pkt)
    assert r is not None
    assert r["rosctr"] == 3
    assert r["function_code"] == 0x04, (
        f"Expected func_code=0x04 (Read Variable) for ROSCTR=3, got {r['function_code']!r}"
    )
    assert r["function_name"] == "Read Variable"
    assert r["is_write"] is False


# ── IEC-104 ──────────────────────────────────────────────────────────────────

def _iec104_pkt(ctrl1, ctrl2=0, ctrl3=0, ctrl4=0, body=b""):
    # APDU: start byte 0x68 + length + 4 control bytes + body
    length = 4 + len(body)
    return bytes([0x68, length, ctrl1, ctrl2, ctrl3, ctrl4]) + body


def test_iec104_u_frame_startdt():
    # U-frame: ctrl1 bit 0 = 1 and bit 1 = 1 (U-frame marker)
    pkt = _iec104_pkt(0x07)
    r = parse_iec104(pkt)
    assert r is not None
    assert r["frame_type"] == "U"


def test_iec104_i_frame_with_asdu():
    # I-frame: ctrl1 bit 0 = 0
    # ASDU layout: type_id[6]=45, VSQ[7]=1, COT[8:10]=[6,0], CA[10:12]=[1,0], IOA[12:15]=[1,0,0]
    # CA little-endian = 1.  The old code read [11:13] which would yield 256.
    asdu = bytes([45, 1, 6, 0, 1, 0, 1, 0, 0])
    pkt = _iec104_pkt(0x00, 0x00, 0x00, 0x00, asdu)
    r = parse_iec104(pkt)
    assert r is not None
    assert r["frame_type"] == "I"
    assert r["type_id"] == 45
    assert r["is_write"] is True  # type_id 45-50 with COT=6
    assert r["common_address"] == 1, (
        f"Expected common_address=1 but got {r['common_address']!r} — "
        "check ASDU offset: CA is at payload_bytes[10:12], not [11:13]"
    )


def test_iec104_invalid_start():
    assert parse_iec104(b"\x69\x04" + b"\x00" * 10) is None


# ── Helpers ───────────────────────────────────────────────────────────────────

def test_modbus_write_multiple_registers():
    pkt = _modbus_pkt(1, 1, 16, struct.pack(">HH", 50, 5) + b"\x0a" + bytes(10))
    r = parse_modbus(pkt)
    assert r["function_code"] == 16
    assert r["is_write"] is True
    assert r["register_address"] == 50
    assert r["quantity"] == 5


# ── EtherNet/IP ───────────────────────────────────────────────────────────────

def _enip_hdr(command, session_handle=0, status=0, data=b""):
    """Build a minimal EtherNet/IP encapsulation header (24 bytes) + optional data."""
    length = len(data)
    sender_context = b"\x00" * 8
    options = 0
    hdr = struct.pack("<HHIIQ I",
        command, length, session_handle, status,
        int.from_bytes(sender_context, "little"), options)
    return hdr + data


def test_enip_register_session():
    pkt = _enip_hdr(0x0065, session_handle=0)
    r = parse_enip(pkt)
    assert r is not None
    assert r["command"] == 0x0065
    assert r["command_name"] == "Register Session"
    assert r["is_error"] is False
    assert r["is_write"] is False


def _enip_send_rr(cip_service_byte):
    """Build a Send RR Data payload whose CIP service byte lands at data[10].
    Parser uses cip_offset=10: interface_handle(4)+timeout(2)+item_count(2)+null_type(2)=10 bytes."""
    cpf = struct.pack("<IHHH", 0, 0, 2, 0x0000) + bytes([cip_service_byte])
    return _enip_hdr(0x006F, data=cpf)


def test_enip_send_rr_data_read_tag():
    pkt = _enip_send_rr(0x4C)
    r = parse_enip(pkt)
    assert r is not None
    assert r["command_name"] == "Send RR Data"
    assert r["cip_service"] == 0x4C
    assert r["cip_service_name"] == "Read Tag"
    assert r["is_write"] is False
    assert r["is_response"] is False


def test_enip_send_rr_data_write_tag():
    pkt = _enip_send_rr(0x4D)
    r = parse_enip(pkt)
    assert r is not None
    assert r["cip_service"] == 0x4D
    assert r["cip_service_name"] == "Write Tag"
    assert r["is_write"] is True


def test_enip_error_status():
    pkt = _enip_hdr(0x0065, status=0x0008)  # non-zero status = error
    r = parse_enip(pkt)
    assert r is not None
    assert r["is_error"] is True


def test_enip_too_short():
    assert parse_enip(b"\x65\x00\x04\x00") is None


def test_enip_empty():
    assert parse_enip(b"") is None
    assert parse_enip(None) is None


def test_enip_unknown_command():
    pkt = _enip_hdr(0x9999)
    r = parse_enip(pkt)
    assert r is not None
    assert "Unknown" in r["command_name"]


# ── TLS ClientHello parser ────────────────────────────────────────────────────

def _build_tls_client_hello(sni=None, ciphers=None, version=0x0303,
                             client_version=0x0303):
    """Build a minimal TLS ClientHello payload bytes for testing."""
    ciphers = ciphers or [0x002F, 0x0035]  # RSA-AES128, RSA-AES256
    random_bytes = b'\xAA' * 32

    # session_id (empty)
    session_id = b'\x00'

    # cipher_suites
    cs_bytes = b''
    for c in ciphers:
        cs_bytes += struct.pack('!H', c)
    cipher_suites = struct.pack('!H', len(cs_bytes)) + cs_bytes

    # compression_methods (null)
    compression = b'\x01\x00'

    # extensions
    extensions = b''

    # SNI extension (type 0)
    if sni:
        sni_bytes = sni.encode('utf-8')
        sni_ext_data = (
            struct.pack('!H', len(sni_bytes) + 3) +  # server_name_list_length
            b'\x00' +                                  # type = host_name
            struct.pack('!H', len(sni_bytes)) +        # server_name_length
            sni_bytes
        )
        extensions += struct.pack('!HH', 0x0000, len(sni_ext_data)) + sni_ext_data

    # supported_groups extension (type 0x000A) — curves 0x0017, 0x0018
    curves_bytes = struct.pack('!HH', 0x0017, 0x0018)
    curves_ext_data = struct.pack('!H', len(curves_bytes)) + curves_bytes
    extensions += struct.pack('!HH', 0x000A, len(curves_ext_data)) + curves_ext_data

    # ec_point_formats extension (type 0x000B)
    pf_ext_data = b'\x01\x00'  # 1 format: uncompressed
    extensions += struct.pack('!HH', 0x000B, len(pf_ext_data)) + pf_ext_data

    # ClientHello body
    ch_body = (
        struct.pack('!H', client_version) +  # client_version
        random_bytes +                         # random
        session_id +                           # session_id
        cipher_suites +                        # cipher_suites
        compression +                          # compression_methods
        struct.pack('!H', len(extensions)) +   # extensions_length
        extensions                             # extensions
    )

    # Handshake header (ClientHello = 0x01)
    hs = b'\x01' + struct.pack('!I', len(ch_body))[1:] + ch_body  # 3-byte len

    # TLS record header
    record = (
        b'\x16' +                              # content_type = Handshake
        struct.pack('!H', version) +           # version
        struct.pack('!H', len(hs)) +           # length
        hs
    )
    return record


def test_tls_clienthello_basic():
    payload = _build_tls_client_hello(sni="example.com")
    r = parse_tls_client_hello(payload)
    assert r is not None
    assert r["sni"] == "example.com"
    assert r["ja3"] is not None
    assert len(r["ja3"]) == 32  # MD5 hex string


def test_tls_clienthello_ja3_deterministic():
    payload = _build_tls_client_hello(sni="test.local")
    r1 = parse_tls_client_hello(payload)
    r2 = parse_tls_client_hello(payload)
    assert r1["ja3"] == r2["ja3"]


def test_tls_clienthello_no_sni():
    payload = _build_tls_client_hello(sni=None)
    r = parse_tls_client_hello(payload)
    assert r is not None
    assert r["sni"] is None
    assert r["ja3"] is not None


def test_tls_clienthello_tls_version():
    payload = _build_tls_client_hello(client_version=0x0303)
    r = parse_tls_client_hello(payload)
    assert r is not None
    assert r["tls_version"] == 0x0303


def test_tls_clienthello_too_short():
    assert parse_tls_client_hello(b'\x16\x03\x03\x00\x05') is None


def test_tls_clienthello_not_tls():
    assert parse_tls_client_hello(b'GET / HTTP/1.1\r\n') is None


def test_tls_clienthello_not_client_hello():
    # ServerHello has msg_type=0x02
    payload = b'\x16\x03\x03' + b'\x00\x05' + b'\x02' + b'\x00\x00\x01\x00'
    assert parse_tls_client_hello(payload) is None


def test_is_grease_values():
    # GREASE values should return True
    for v in [0x0A0A, 0x1A1A, 0x2A2A, 0xFAFA, 0xAAAA]:
        assert _is_grease(v), f"Expected {v:#06x} to be GREASE"
    # Non-GREASE values
    for v in [0x002F, 0x0035, 0x0000, 0x0017]:
        assert not _is_grease(v), f"Expected {v:#06x} to NOT be GREASE"


# ── Bug-sweep regression tests (B4, B5, B7) ──────────────────────────────────

def test_modbus_no_func_code_returns_none():
    """B5: parse_modbus must return None for a payload with no function code byte (<=7 bytes)."""
    # 7-byte payload: MBAP header only (transaction=1, protocol=0, length=1, unit=1), no FC byte
    payload = struct.pack(">HHHB", 1, 0, 1, 1)  # exactly 7 bytes
    assert parse_modbus(payload) is None, "7-byte Modbus payload (no FC) must return None"


def test_modbus_is_response_not_in_parser_output():
    """B4: parse_modbus must not set is_response (it's computed directionally in analyze_pcap)."""
    pkt = _modbus_pkt(1, 1, 3, struct.pack(">HH", 100, 10))
    r = parse_modbus(pkt)
    assert r is not None
    assert "is_response" not in r, "parse_modbus must not set is_response"


def test_modbus_is_response_not_set_for_error_response():
    """B4: error response must also not have is_response field from the parser."""
    pkt = _modbus_pkt(3, 1, 0x83, bytes([2]))
    r = parse_modbus(pkt)
    assert r is not None
    assert r["is_error"] is True
    assert "is_response" not in r, "parse_modbus must not set is_response even for error frames"


def test_coap_truncated_option_no_crash():
    """B7: CoAP parser must not crash or over-read on a truncated option value."""
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from app import parse_coap
    # Valid CoAP header (4 bytes) + option delta=11 (Uri-Path), length=20, but only 3 bytes of value
    # Option byte: delta=0xB (11), length=0x3 — then only 3 value bytes, rest truncated
    header = bytes([0x40, 0x01, 0x00, 0x01])  # Ver=1, T=CON, TKL=0, Code=0.01 GET, MsgID=1
    # Option: delta nibble=0xB (11=Uri-Path), length nibble=0xF4 (extends: 0xF → length=20+13=33)
    # but payload only has 3 bytes after the extension byte — truncated
    option_byte = bytes([0xBD])   # delta=0xB(11), length nibble=D(13→extended)
    ext_len = bytes([0x00])       # extended length = 0+13=13 bytes, but...
    tiny_payload = bytes([0x61, 0x62, 0x63])  # only 3 bytes of a 13-byte option value
    payload = header + option_byte + ext_len + tiny_payload
    # Must not raise; may return None or a partial result
    try:
        result = parse_coap(payload)
        # If it returns something, it should be a dict or None
        assert result is None or isinstance(result, dict)
    except Exception as e:
        assert False, f"parse_coap raised on truncated option: {e}"


# ── MQTT ──────────────────────────────────────────────────────────────────────

def _mqtt_subscribe(message_id, topics):
    """Build a minimal MQTT SUBSCRIBE payload (no fixed-header wrapper needed for parse_mqtt)."""
    from app import parse_mqtt
    # Fixed header: packet type 8 (SUBSCRIBE), flags 0x02; remaining length follows
    topic_bytes = b""
    for topic, qos in topics:
        t_enc = topic.encode("utf-8")
        topic_bytes += struct.pack(">H", len(t_enc)) + t_enc + bytes([qos])
    # Remaining = 2 (message_id) + topic_bytes
    remaining = struct.pack(">H", message_id) + topic_bytes
    remaining_len = len(remaining)
    assert remaining_len < 128, "test helper only supports 1-byte remaining length"
    return bytes([0x82, remaining_len]) + remaining


def test_mqtt_subscribe_single_topic():
    """parse_mqtt must capture a SUBSCRIBE topic correctly."""
    from app import parse_mqtt
    payload = _mqtt_subscribe(1, [("/sensor/temp", 0)])
    r = parse_mqtt(payload)
    assert r is not None
    assert r["type"] == 8           # msg_type integer
    assert r["type_name"] == "SUBSCRIBE"
    assert "/sensor/temp" in r["details"].get("topics", "")


def test_mqtt_subscribe_topic_at_buffer_end():
    """L1 fix: a topic whose bytes end exactly at the buffer boundary must be captured.

    Before the fix, ``while p_idx + 2 < len(payload)`` used strict-less-than, which
    caused the loop to exit one iteration early when the last topic occupied the final
    two bytes (the length prefix).  The corrected guard is ``<= len(payload)``.
    """
    from app import parse_mqtt
    # Build a SUBSCRIBE with two topics; the second topic ends exactly at buffer boundary.
    payload = _mqtt_subscribe(42, [("a/b", 1), ("x/y", 0)])
    r = parse_mqtt(payload)
    assert r is not None
    topics_str = r["details"].get("topics", "")
    assert "x/y" in topics_str, (
        f"Second topic 'x/y' ending at buffer boundary was not captured; got: {topics_str!r}"
    )
