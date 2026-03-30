"""Tests for routes/health.py — /api/health endpoint.

Critical: deps.py creates DB connections at import time.
We must mock the deps module BEFORE importing api.py.
"""

import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def client(monkeypatch):
    """Create a FastAPI TestClient with mocked deps module.

    This fixture patches deps.py's import-time side effects so that
    importing api.py does not attempt real DB connections.
    Reusable pattern for all route tests (Phase 3).
    """
    # Remove cached route modules so each test gets a fresh import
    for mod_name in list(sys.modules):
        if mod_name.startswith('routes'):
            monkeypatch.delitem(sys.modules, mod_name, raising=False)

    # Create a fake deps module to prevent import-time DB connection
    mock_deps = MagicMock()
    mock_deps.APP_VERSION = '3.1.0-test'
    mock_deps.get_conn = MagicMock()
    mock_deps.put_conn = MagicMock()
    mock_deps.enricher_db = MagicMock()
    mock_deps.abuseipdb = MagicMock()
    mock_deps.unifi_api = MagicMock()

    # Patch deps in sys.modules before any route imports
    monkeypatch.setitem(sys.modules, 'deps', mock_deps)

    # Also need to patch db module to avoid psycopg2 import issues
    mock_db_module = MagicMock()
    mock_db_module.get_config = MagicMock(return_value=None)
    mock_db_module.is_external_db = MagicMock(return_value=False)
    monkeypatch.setitem(sys.modules, 'db', mock_db_module)

    # Now we can safely import and create the test client
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from routes.health import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app), mock_deps, mock_db_module


class TestHealthEndpoint:
    def test_health_ok(self, client):
        test_client, mock_deps, _mock_db = client

        # Mock the DB cursor to return log stats
        # Health endpoint issues 3 queries: pg_class count, MIN/MAX timestamps, db size
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        oldest = datetime(2026, 1, 1, tzinfo=timezone.utc)
        latest = datetime(2026, 3, 5, tzinfo=timezone.utc)
        mock_cursor.fetchone.side_effect = [
            (1000,),            # pg_class reltuples count
            (oldest, latest),   # MIN/MAX timestamps
            (1024 * 1024,),     # pg_database_size
        ]
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
        mock_deps.get_conn.return_value = mock_conn

        resp = test_client.get('/api/health')
        assert resp.status_code == 200
        data = resp.json()
        assert data['status'] == 'ok'
        assert data['version'] == '3.1.0-test'
        assert data['total_logs'] == 1000
        assert data['oldest_log_at'] == '2026-01-01T00:00:00+00:00'
        assert data['retention_days'] == 60  # default

    def test_health_db_failure(self, client):
        test_client, mock_deps, _mock_db = client

        mock_conn = MagicMock()
        mock_conn.cursor.side_effect = Exception('DB down')
        mock_deps.get_conn.return_value = mock_conn

        resp = test_client.get('/api/health')
        assert resp.status_code == 503
        assert resp.json()['detail'] == 'Service unavailable'
