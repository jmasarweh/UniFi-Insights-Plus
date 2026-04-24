"""Shared fixtures for backend tests."""

import pytest


@pytest.fixture(autouse=True)
def _reset_parser_globals(monkeypatch):
    """Reset mutable parser module-level state between tests."""
    import parsers
    monkeypatch.setattr(parsers, '_wan_ip', None)
    monkeypatch.setattr(parsers, 'WAN_IPS', set())
    monkeypatch.setattr(parsers, '_wan_ip_by_iface_present', False)
    monkeypatch.setattr(parsers, 'WAN_INTERFACES', {'ppp0'})
    monkeypatch.setattr(parsers, 'INTERFACE_LABELS', {})


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Ensure DB/encryption env vars don't leak between tests."""
    for var in ('SECRET_KEY', 'POSTGRES_PASSWORD', 'DB_HOST', 'DB_PORT',
                'DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_SSLMODE',
                'DB_SSLROOTCERT', 'DB_SSLCERT', 'DB_SSLKEY', 'TZ',
                'RETENTION_CLEANUP_TIME', 'RETENTION_TIME',
                'RETENTION_DAYS', 'DNS_RETENTION_DAYS'):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(autouse=True)
def _reset_legacy_retention_time_warned():
    """Reset the once-per-process deprecation-warning flag between tests so
    the legacy RETENTION_TIME fallback test can assert its warning fires."""
    try:
        import db
        db._legacy_retention_time_warned = False
    except ImportError:
        # db module not importable in this test env (e.g. route-only tests
        # that mock sys.modules['db']). Nothing to reset.
        pass
