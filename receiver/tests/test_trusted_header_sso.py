"""Tests for opt-in trusted-header SSO in routes/auth.py.

routes.auth is imported with `db` and `deps` replaced by stubs, and the DB
connection is a small fake that records SQL, so no Postgres is needed.
"""

import hashlib
import hmac
import importlib
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

PG = 'test-postgres-password'
TOKEN = hmac.new(PG.encode(), b'proxy-auth', hashlib.sha256).hexdigest()
ROLES = {'admin': 1, 'viewer': 2}


class FakeCursor:
    def __init__(self, store):
        self.store = store
        self._result = None
        self.rowcount = 0

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        s = ' '.join(sql.split()).lower()
        self.rowcount = 0
        if s.startswith('select id from roles'):
            rid = ROLES.get(params[0])
            self._result = {'id': rid} if rid else None
        elif s.startswith('insert into users'):
            name = params[0]
            if name not in self.store['users']:
                self.store['users'][name] = {'role_id': params[2], 'is_active': True,
                                             'hash': params[1]}
                self.rowcount = 1
            self.store['inserts'] += 1
        elif s.startswith('select u.id as user_id'):
            u = self.store['users'].get(params[0])
            if u is None:
                self._result = None
            else:
                role = {v: k for k, v in ROLES.items()}[u['role_id']]
                self._result = {'user_id': 7, 'username': params[0], 'role_id': u['role_id'],
                                'is_active': u['is_active'], 'role_name': role, 'permissions': '[]'}
        else:
            self._result = None

    def fetchone(self):
        return self._result


class FakeConn:
    def __init__(self, store):
        self.store = store

    def cursor(self, cursor_factory=None):
        return FakeCursor(self.store)

    def commit(self):
        self.store['commits'] += 1

    def rollback(self):
        pass


@pytest.fixture
def auth(monkeypatch):
    """Import routes.auth fresh with SSO env set and DB stubbed."""
    store = {'users': {}, 'inserts': 0, 'commits': 0}
    monkeypatch.setenv('POSTGRES_PASSWORD', PG)
    monkeypatch.setenv('SSO_TRUSTED_HEADER', 'X-Auth-Request-Email')
    monkeypatch.setenv('SSO_ADMIN_EMAILS', 'Boss@Example.com, other@example.com')
    deps = SimpleNamespace(get_conn=lambda: FakeConn(store), put_conn=lambda c: None,
                           enricher_db=MagicMock())
    monkeypatch.setitem(sys.modules, 'deps', deps)
    monkeypatch.setitem(sys.modules, 'db', SimpleNamespace(get_config=MagicMock(return_value=True),
                                                           set_config=MagicMock()))
    monkeypatch.delitem(sys.modules, 'routes.auth', raising=False)
    mod = importlib.import_module('routes.auth')
    monkeypatch.setattr(mod, '_write_audit', MagicMock())
    mod._test_store = store
    return mod


def req(headers, path='/api/logs'):
    h = {k.lower(): v for k, v in headers.items()}
    return SimpleNamespace(headers=h, cookies={}, client=SimpleNamespace(host='172.19.0.4'),
                           url=SimpleNamespace(path=path, scheme='http'))


def trusted(email):
    return req({'X-ULI-Proxy-Auth': TOKEN, 'X-Auth-Request-Email': email})


class TestEmailExtraction:
    def test_trusted_header_accepted_and_lowercased(self, auth):
        assert auth._sso_email_from_request(trusted('Jane.Doe@Example.com')) == 'jane.doe@example.com'

    def test_header_ignored_without_proxy_secret(self, auth):
        assert auth._sso_email_from_request(req({'X-Auth-Request-Email': 'jane@example.com'})) is None

    def test_header_ignored_with_wrong_proxy_secret(self, auth):
        r = req({'X-ULI-Proxy-Auth': 'nope', 'X-Auth-Request-Email': 'jane@example.com'})
        assert auth._sso_email_from_request(r) is None

    @pytest.mark.parametrize('bad', ['', 'jane', 'a@b@c.com', '@example.com', 'jane@localhost',
                                     'ja ne@example.com', 'x' * 95 + '@e.com'])
    def test_malformed_rejected(self, auth, bad):
        assert auth._sso_email_from_request(trusted(bad)) is None

    def test_feature_off_when_env_unset(self, auth, monkeypatch):
        monkeypatch.setattr(auth, 'SSO_TRUSTED_HEADER', '')
        assert auth._sso_email_from_request(trusted('jane@example.com')) is None


class TestSsoUser:
    def test_first_visit_creates_viewer(self, auth):
        info = auth._sso_user(trusted('jane@example.com'))
        assert info['role_name'] == 'viewer' and info['username'] == 'jane@example.com'
        assert auth._test_store['users']['jane@example.com']['role_id'] == ROLES['viewer']
        auth._write_audit.assert_called_once()

    def test_admin_list_gets_admin(self, auth):
        assert auth._sso_user(trusted('boss@example.com'))['role_name'] == 'admin'

    def test_second_visit_reuses_user(self, auth):
        auth._sso_user(trusted('jane@example.com'))
        auth._sso_user(trusted('jane@example.com'))
        assert auth._test_store['inserts'] == 1
        assert auth._write_audit.call_count == 1

    def test_db_role_is_authoritative_after_creation(self, auth):
        auth._test_store['users']['boss@example.com'] = {'role_id': ROLES['viewer'], 'is_active': True, 'hash': 'x'}
        assert auth._sso_user(trusted('boss@example.com'))['role_name'] == 'viewer'

    def test_deactivated_user_refused(self, auth):
        auth._test_store['users']['jane@example.com'] = {'role_id': ROLES['viewer'], 'is_active': False, 'hash': 'x'}
        assert auth._sso_user(trusted('jane@example.com')) is None

    def test_password_hash_is_random_bcrypt(self, auth):
        auth._sso_user(trusted('jane@example.com'))
        assert auth._test_store['users']['jane@example.com']['hash'].startswith('$2')

    def test_untrusted_request_creates_nothing(self, auth):
        assert auth._sso_user(req({'X-Auth-Request-Email': 'evil@example.com'})) is None
        assert auth._test_store['inserts'] == 0


class TestRequireAuth:
    def test_require_auth_accepts_sso(self, auth, monkeypatch):
        monkeypatch.setattr(auth, '_auth_enabled', lambda: True)
        assert auth.require_auth(trusted('jane@example.com'))['username'] == 'jane@example.com'

    def test_require_auth_still_401_without_identity(self, auth, monkeypatch):
        monkeypatch.setattr(auth, '_auth_enabled', lambda: True)
        with pytest.raises(auth.HTTPException) as e:
            auth.require_auth(req({'X-ULI-Proxy-Auth': TOKEN}))
        assert e.value.status_code == 401
