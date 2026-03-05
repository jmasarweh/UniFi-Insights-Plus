"""Tests for services.py — IANA service name lookups."""

from services import get_service_name, get_service_description


class TestGetServiceName:
    def test_http(self):
        # IANA CSV maps port 80 to 'www', not 'http'
        assert get_service_name(80, 'tcp') == 'www'

    def test_https(self):
        assert get_service_name(443, 'tcp') == 'https'

    def test_case_insensitive_protocol(self):
        assert get_service_name(80, 'TCP') == 'www'

    def test_dns_display_override(self):
        # domain → DNS via _DISPLAY_OVERRIDES
        result = get_service_name(53, 'udp')
        assert result == 'DNS'

    def test_none_port(self):
        assert get_service_name(None, 'tcp') is None

    def test_unknown_port(self):
        # Port 99999 is not in IANA
        assert get_service_name(99999, 'tcp') is None

    def test_default_protocol(self):
        # Default protocol is tcp; IANA CSV maps port 80 to 'www'
        assert get_service_name(80) == 'www'


class TestGetServiceDescription:
    def test_known_port(self):
        desc = get_service_description(80, 'tcp')
        # Description may or may not differ from name; just test it doesn't error
        # and returns None or a string
        assert desc is None or isinstance(desc, str)

    def test_none_port(self):
        assert get_service_description(None) is None

    def test_unknown_port(self):
        assert get_service_description(99999, 'tcp') is None
