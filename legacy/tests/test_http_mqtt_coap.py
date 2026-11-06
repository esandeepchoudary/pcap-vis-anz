"""Unit tests for parse_http, parse_mqtt, and parse_coap."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import parse_http, parse_mqtt, parse_coap


# ── parse_http ────────────────────────────────────────────────────────────────

def _enc(s):
    return s.encode()


def test_http_get_request():
    raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"
    r = parse_http(raw, "HTTP")
    assert r is not None
    assert r["type"] == "request"
    assert r["method"] == "GET"
    assert r["url"] == "/index.html"
    assert r["version"] == "HTTP/1.1"
    assert r["headers"]["Host"] == "example.com"
    assert r["headers"]["User-Agent"] == "test"


def test_http_post_with_body():
    raw = b"POST /login HTTP/1.1\r\nContent-Length: 14\r\n\r\nuser=foo&pw=1"
    r = parse_http(raw, "HTTP")
    assert r["type"] == "request"
    assert r["method"] == "POST"
    assert r["url"] == "/login"
    assert "user=foo" in r["body_preview"]


def test_http_all_methods():
    for method in ("PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"):
        raw = f"{method} /path HTTP/1.1\r\n\r\n".encode()
        r = parse_http(raw, "HTTP")
        assert r is not None
        assert r["method"] == method


def test_http_200_response():
    raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>"
    r = parse_http(raw, "HTTP")
    assert r is not None
    assert r["type"] == "response"
    assert r["status_code"] == 200
    assert r["reason"] == "OK"
    assert r["headers"]["Content-Type"] == "text/html"
    assert "<html>" in r["body_preview"]


def test_http_404_response():
    raw = b"HTTP/1.1 404 Not Found\r\n\r\n"
    r = parse_http(raw, "HTTP")
    assert r["type"] == "response"
    assert r["status_code"] == 404
    assert r["reason"] == "Not Found"


def test_http_empty_bytes():
    assert parse_http(b"", "HTTP") is None
    assert parse_http(None, "HTTP") is None


def test_http_non_http_payload():
    raw = b"\x00\x01\x02\x03binary data"
    r = parse_http(raw, "HTTP")
    assert r is None


def test_http_response_no_body():
    raw = b"HTTP/1.1 304 Not Modified\r\nETag: abc\r\n\r\n"
    r = parse_http(raw, "HTTP")
    assert r["status_code"] == 304


def test_http_request_body_preview_capped():
    long_body = "x" * 1000
    raw = f"POST /upload HTTP/1.1\r\n\r\n{long_body}".encode()
    r = parse_http(raw, "HTTP")
    assert len(r["body_preview"]) <= 500


# ── parse_mqtt ────────────────────────────────────────────────────────────────

def _mqtt_connect(client_id=b"test-client"):
    proto_name = b"MQTT"
    proto_name_field = len(proto_name).to_bytes(2, "big") + proto_name
    # protocol level 4, connect flags (clean session=1), keepalive=60
    variable_header = proto_name_field + bytes([4, 0x02, 0, 60])
    client_id_field = len(client_id).to_bytes(2, "big") + client_id
    payload = client_id_field
    remaining = len(variable_header) + len(payload)
    return bytes([0x10, remaining]) + variable_header + payload


def _mqtt_publish(topic, message=b"hello"):
    topic_bytes = topic.encode() if isinstance(topic, str) else topic
    topic_field = len(topic_bytes).to_bytes(2, "big") + topic_bytes
    payload_data = topic_field + message
    return bytes([0x30, len(payload_data)]) + payload_data


def _mqtt_subscribe(topic):
    topic_bytes = topic.encode() if isinstance(topic, str) else topic
    msg_id = b"\x00\x01"
    topic_field = len(topic_bytes).to_bytes(2, "big") + topic_bytes + bytes([0])  # QoS 0
    payload_data = msg_id + topic_field
    return bytes([0x82, len(payload_data)]) + payload_data


def _mqtt_connack(return_code=0):
    return bytes([0x20, 0x02, 0x00, return_code])


def test_mqtt_connect():
    pkt = _mqtt_connect(client_id=b"my-device")
    r = parse_mqtt(pkt)
    assert r is not None
    assert r["type_name"] == "CONNECT"
    assert r["details"]["client_id"] == "my-device"
    assert r["details"]["clean_session"] is True
    assert r["details"]["has_credentials"] is False


def test_mqtt_connack_accepted():
    pkt = _mqtt_connack(0)
    r = parse_mqtt(pkt)
    assert r is not None
    assert r["type_name"] == "CONNACK"
    assert r["details"]["return_code"] == "Connection Accepted"
    assert r["details"]["session_present"] is False


def test_mqtt_connack_refused():
    pkt = _mqtt_connack(4)
    r = parse_mqtt(pkt)
    assert r["details"]["return_code"] == "Refused: Bad Credentials"


def test_mqtt_publish():
    pkt = _mqtt_publish("sensors/temp", b"25.3")
    r = parse_mqtt(pkt)
    assert r is not None
    assert r["type_name"] == "PUBLISH"
    assert r["details"]["topic"] == "sensors/temp"
    assert "25.3" in r["details"]["payload_preview"]


def test_mqtt_subscribe():
    pkt = _mqtt_subscribe("home/lights/#")
    r = parse_mqtt(pkt)
    assert r is not None
    assert r["type_name"] == "SUBSCRIBE"
    assert "home/lights/#" in r["details"]["topics"]


def test_mqtt_too_short():
    assert parse_mqtt(b"\x10") is None
    assert parse_mqtt(None) is None
    assert parse_mqtt(b"") is None


def test_mqtt_pingreq():
    pkt = bytes([0xC0, 0x00])  # PINGREQ, remaining length 0
    r = parse_mqtt(pkt)
    assert r is not None
    assert r["type_name"] == "PINGREQ"


def test_mqtt_disconnect():
    pkt = bytes([0xE0, 0x00])
    r = parse_mqtt(pkt)
    assert r is not None
    assert r["type_name"] == "DISCONNECT"


# ── parse_coap ────────────────────────────────────────────────────────────────

def _coap_pkt(msg_type, code_class, code_detail, token=b"", options=b"", payload=b""):
    """Build a minimal CoAP packet."""
    version = 1
    token_len = len(token)
    first_byte = (version << 6) | (msg_type << 4) | token_len
    code_byte = (code_class << 5) | code_detail
    msg_id = 0x1234
    hdr = bytes([first_byte, code_byte, (msg_id >> 8) & 0xFF, msg_id & 0xFF])
    data = hdr + token + options
    if payload:
        data += b"\xFF" + payload
    return data


def test_coap_con_get():
    # CON (0), GET (0.01 = class 0, detail 1)
    pkt = _coap_pkt(msg_type=0, code_class=0, code_detail=1)
    r = parse_coap(pkt)
    assert r is not None
    assert r["type"] == "CON"
    assert r["code"] == "0.01"
    assert r["code_name"] == "GET"
    assert r["is_request"] is True


def test_coap_non_post():
    pkt = _coap_pkt(msg_type=1, code_class=0, code_detail=2)
    r = parse_coap(pkt)
    assert r["type"] == "NON"
    assert r["code_name"] == "POST"


def test_coap_ack_response_content():
    # ACK (2), 2.05 Content (class=2, detail=5)
    pkt = _coap_pkt(msg_type=2, code_class=2, code_detail=5)
    r = parse_coap(pkt)
    assert r["type"] == "ACK"
    assert r["code"] == "2.05"
    assert r["code_name"] == "Content"
    assert r["is_request"] is False


def test_coap_rst():
    pkt = _coap_pkt(msg_type=3, code_class=0, code_detail=0)
    r = parse_coap(pkt)
    assert r["type"] == "RST"


def test_coap_delete_method():
    pkt = _coap_pkt(msg_type=0, code_class=0, code_detail=4)
    r = parse_coap(pkt)
    assert r["code_name"] == "DELETE"


def test_coap_uri_path_option():
    # Uri-Path option: option number 11, delta=11, len=6 for "/hello"
    # Single option byte: (11 << 4) | 6 = 0xB6, then "sensors"
    opt = bytes([0xB7]) + b"sensors"  # delta=11, len=7
    pkt = _coap_pkt(msg_type=0, code_class=0, code_detail=1, options=opt)
    r = parse_coap(pkt)
    assert r["details"]["uri"] == "/sensors"


def test_coap_payload():
    pkt = _coap_pkt(msg_type=2, code_class=2, code_detail=5, payload=b"temperature=23")
    r = parse_coap(pkt)
    assert "temperature=23" in r["details"]["payload_preview"]


def test_coap_too_short():
    assert parse_coap(b"\x40\x01\x00") is None
    assert parse_coap(None) is None
    assert parse_coap(b"") is None


def test_coap_wrong_version():
    # Version != 1 should return None
    bad = bytes([0x80, 0x01, 0x00, 0x00])  # version=2
    assert parse_coap(bad) is None


def test_coap_404_response():
    # 4.04 Not Found: class=4, detail=4
    pkt = _coap_pkt(msg_type=2, code_class=4, code_detail=4)
    r = parse_coap(pkt)
    assert r["code"] == "4.04"
    assert r["code_name"] == "Not Found"
    assert r["is_request"] is False
