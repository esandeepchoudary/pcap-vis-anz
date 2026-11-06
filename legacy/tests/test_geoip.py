"""Tests for the bundled GeoIP database and geo_lookup() behaviour."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

geoip2 = pytest.importorskip("geoip2", reason="geoip2 not installed")

# Skip the whole module if the bundled DB is absent (keeps the suite robust on
# machines that only run pure-Python tests without the data/ directory).
_BUNDLED_DB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data", "dbip-country-lite.mmdb",
)
pytestmark = pytest.mark.skipif(
    not os.path.isfile(_BUNDLED_DB),
    reason="Bundled dbip-country-lite.mmdb not present",
)


def _reset_geoip_state():
    """Reset the module-level GeoIP singleton so each test starts clean."""
    import app as app_module
    import threading
    app_module._geoip_reader = None
    app_module._geoip_is_city = False
    app_module._geoip_lock = threading.Lock()
    app_module.geo_lookup.cache_clear()


# ── Reader / availability ──────────────────────────────────────────────────────

def test_bundled_db_opens():
    """The bundled DB-IP Country Lite .mmdb must be openable by geoip2."""
    import geoip2.database
    reader = geoip2.database.Reader(_BUNDLED_DB)
    assert reader is not None
    db_type = reader.metadata().database_type
    # DB-IP Country Lite uses "DBIP-Country-Lite" or similar — must contain "Country"
    assert "Country" in db_type or "country" in db_type.lower(), (
        f"Unexpected database_type: {db_type!r}"
    )


def test_get_geoip_reader_returns_reader():
    """_get_geoip_reader() must return a non-None reader with the bundled DB present."""
    _reset_geoip_state()
    from app import _get_geoip_reader
    reader = _get_geoip_reader()
    assert reader is not None, "_get_geoip_reader() returned None — bundled DB not loaded"


def test_geoip_available_true(tmp_path):
    """analyze_pcap() must report geoip_available=True when the bundled DB is present."""
    from tests.conftest import _pcap_header, _pcap_record, _eth_ip_tcp
    from app import analyze_pcap
    _reset_geoip_state()

    # One packet between two private hosts (no geo needed) — we just check the flag
    frame = _eth_ip_tcp("10.0.0.1", "10.0.0.2")
    path = str(tmp_path / "test.pcap")
    with open(path, "wb") as f:
        f.write(_pcap_header())
        f.write(_pcap_record(frame))

    result = analyze_pcap(path)
    assert result["stats"]["geoip_available"] is True, (
        f"geoip_available is not True: {result['stats']}"
    )


# ── geo_lookup() correctness ───────────────────────────────────────────────────

def test_geo_lookup_google_dns():
    """geo_lookup('8.8.8.8') must return US country_code using the bundled Country DB."""
    _reset_geoip_state()
    from app import geo_lookup
    result = geo_lookup("8.8.8.8")
    assert result is not None, "geo_lookup returned None for 8.8.8.8"
    assert result["country_code"] == "US", (
        f"Expected country_code='US', got {result['country_code']!r}"
    )
    assert result["country"] is not None and len(result["country"]) > 0, (
        "country name should be non-empty"
    )


def test_geo_lookup_country_db_has_no_city():
    """With the Country Lite DB, city/lat/lon must be None (not a City-level DB)."""
    _reset_geoip_state()
    from app import geo_lookup, _geoip_is_city
    # Force the bundled (non-city) DB to be used
    import app as app_module
    # Ensure bundled DB is selected, not a system City DB
    if _geoip_is_city:
        pytest.skip("A City-level DB is installed — country-only assertions don't apply")
    result = geo_lookup("8.8.8.8")
    assert result is not None
    assert result["city"] is None, f"city should be None for Country DB, got {result['city']!r}"
    assert result["lat"] is None, f"lat should be None for Country DB, got {result['lat']!r}"
    assert result["lon"] is None, f"lon should be None for Country DB, got {result['lon']!r}"


def test_geo_lookup_returns_none_for_private():
    """Private IPs pass through geo_lookup() but RFC1918 addresses have no geo record."""
    _reset_geoip_state()
    from app import geo_lookup
    # RFC1918 addresses are not in the public DB — lookup either returns None or raises
    result = geo_lookup("192.168.1.1")
    # Either None or a dict with empty/None country_code (both are acceptable "no geo" signals)
    if result is not None:
        assert not result.get("country_code"), (
            f"Unexpected geo for private IP 192.168.1.1: {result}"
        )


def test_geo_lookup_dict_shape():
    """geo_lookup must always return a dict with the expected 5 keys (or None)."""
    _reset_geoip_state()
    from app import geo_lookup
    result = geo_lookup("1.1.1.1")
    if result is not None:
        for key in ("country", "country_code", "city", "lat", "lon"):
            assert key in result, f"Key {key!r} missing from geo_lookup result"
