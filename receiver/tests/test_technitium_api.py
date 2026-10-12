"""Tests for the Technitium poller's Query Logs app selection and cluster
node discovery/fan-out logic."""

import pytest

from technitium_api import TechnitiumPoller


class FakeDB:
    """Minimal stand-in for Database: config map only."""

    def __init__(self, config=None):
        self._config = dict(config or {})
        self.batches = []  # (server_id, cursor, count)

    def get_config(self, key, default=None):
        return self._config.get(key, default)

    def set_config(self, key, value):
        self._config[key] = value

    def insert_technitium_batch(self, logs, server_id, new_cursor):
        self.batches.append((server_id, new_cursor, len(logs)))


APPS = [
    {'name': 'Query Logs (Sqlite)',
     'dnsApps': [{'classPath': 'QueryLogsSqlite.App', 'isQueryLogs': True}]},
    {'name': 'Ad Blocker',
     'dnsApps': [{'classPath': 'AdBlock.App', 'isQueryLogs': False}]},
    {'name': 'Query Logs (PostgreSQL)',
     'dnsApps': [{'classPath': 'QueryLogsPostgreSql.App', 'isQueryLogs': True}]},
]


def make_poller(config=None):
    return TechnitiumPoller(FakeDB(config))


def server(**kw):
    base = {'id': 'srv1', 'name': 'ns00', 'host': 'http://ns00:5380',
            'token': 'tok', 'verify_tls': True, 'app': '', 'cluster': False}
    base.update(kw)
    return base


# ── Query Logs app selection ──────────────────────────────────────────────────

def test_list_query_logs_apps_finds_all_backends():
    found = TechnitiumPoller._list_query_logs_apps(APPS)
    assert found == [('Query Logs (Sqlite)', 'QueryLogsSqlite.App'),
                     ('Query Logs (PostgreSQL)', 'QueryLogsPostgreSql.App')]


def test_find_app_defaults_to_first():
    assert TechnitiumPoller._find_query_logs_app(APPS) == \
        ('Query Logs (Sqlite)', 'QueryLogsSqlite.App')


def test_find_app_honors_preferred_name():
    assert TechnitiumPoller._find_query_logs_app(APPS, 'Query Logs (PostgreSQL)') == \
        ('Query Logs (PostgreSQL)', 'QueryLogsPostgreSql.App')


def test_find_app_preferred_missing_returns_none():
    assert TechnitiumPoller._find_query_logs_app(APPS, 'Nope') is None


def test_discover_app_error_lists_available(monkeypatch):
    poller = make_poller()
    monkeypatch.setattr(poller, '_api_get',
                        lambda srv, path, params, node=None: {'response': {'apps': APPS}})
    with pytest.raises(RuntimeError) as exc:
        poller._discover_app(server(app='Nope'))
    assert 'Nope' in str(exc.value)
    assert 'Query Logs (Sqlite)' in str(exc.value)


def test_discover_app_caches_per_node(monkeypatch):
    poller = make_poller()
    calls = []

    def fake_api(srv, path, params, node=None):
        calls.append(node)
        return {'response': {'apps': APPS}}

    monkeypatch.setattr(poller, '_api_get', fake_api)
    srv = server()
    assert poller._discover_app(srv, 'node-a')[0] == 'Query Logs (Sqlite)'
    assert poller._discover_app(srv, 'node-a')[0] == 'Query Logs (Sqlite)'  # cached
    assert poller._discover_app(srv, 'node-b')[0] == 'Query Logs (Sqlite)'  # own cache slot
    assert calls == ['node-a', 'node-b']


# ── Cluster node discovery ────────────────────────────────────────────────────

def _cluster_state(nodes, initialized=True):
    return {'response': {'clusterInitialized': initialized, 'nodes': nodes}}


def test_cluster_nodes_filters_unreachable(monkeypatch):
    poller = make_poller()
    monkeypatch.setattr(poller, '_api_get', lambda *a, **k: _cluster_state([
        {'name': 'ns00.lan', 'state': 'Self'},
        {'name': 'ns01.lan', 'state': 'Connected'},
        {'name': 'ns02.lan', 'state': 'Unreachable'},
    ]))
    assert poller._get_cluster_nodes(server(cluster=True)) == ['ns00.lan', 'ns01.lan']


def test_cluster_nodes_none_when_not_initialized(monkeypatch):
    poller = make_poller()
    monkeypatch.setattr(poller, '_api_get', lambda *a, **k: _cluster_state([], initialized=False))
    assert poller._get_cluster_nodes(server(cluster=True)) is None


def test_cluster_nodes_none_on_error(monkeypatch):
    poller = make_poller()

    def boom(*a, **k):
        raise ConnectionError('nope')

    monkeypatch.setattr(poller, '_api_get', boom)
    assert poller._get_cluster_nodes(server(cluster=True)) is None


# ── Cluster fan-out and per-node cursors ──────────────────────────────────────

def _entries_page(entries):
    return {'response': {'entries': entries, 'totalPages': 1}}


def test_poll_server_cluster_uses_per_node_cursors(monkeypatch):
    poller = make_poller()
    srv = server(cluster=True)
    poller.servers = [srv]

    monkeypatch.setattr(poller, '_get_cluster_nodes', lambda s: ['ns00.lan', 'ns01.lan'])

    def fake_fetch(s, page, node=None):
        # Each node has its own independent rowNumber sequence
        rows = {'ns00.lan': 500, 'ns01.lan': 7}[node]
        return _entries_page([{'rowNumber': rows, 'timestamp': '2026-07-10T00:00:00Z',
                               'clientIpAddress': '10.0.0.1', 'qname': 'example.com',
                               'qtype': 'A', 'responseType': 'Cached', 'rcode': 'NoError',
                               'protocol': 'Udp', 'answer': 'A 1.2.3.4'}])

    monkeypatch.setattr(poller, '_fetch_page', fake_fetch)
    poller._poll_server(srv)

    assert poller._cursors == {'srv1@ns00.lan': 500, 'srv1@ns01.lan': 7}
    assert sorted(poller._db.batches) == [('srv1@ns00.lan', 500, 1), ('srv1@ns01.lan', 7, 1)]
    status = poller._get_status('srv1')
    assert status['connected'] is True
    assert set(status['nodes']) == {'ns00.lan', 'ns01.lan'}


def test_poll_server_cluster_partial_failure(monkeypatch):
    poller = make_poller()
    srv = server(cluster=True)
    poller.servers = [srv]
    monkeypatch.setattr(poller, '_get_cluster_nodes', lambda s: ['ok.lan', 'bad.lan'])

    def fake_fetch(s, page, node=None):
        if node == 'bad.lan':
            raise ConnectionError('node down')
        return _entries_page([])

    monkeypatch.setattr(poller, '_fetch_page', fake_fetch)
    poller._poll_server(srv)

    status = poller._get_status('srv1')
    assert status['connected'] is False
    assert 'bad.lan' in status['last_error']
    assert status['nodes']['ok.lan']['connected'] is True
    assert status['nodes']['bad.lan']['connected'] is False


def test_poll_server_cluster_falls_back_to_direct(monkeypatch):
    poller = make_poller()
    srv = server(cluster=True)
    poller.servers = [srv]
    monkeypatch.setattr(poller, '_get_cluster_nodes', lambda s: None)
    monkeypatch.setattr(poller, '_fetch_page',
                        lambda s, page, node=None: _entries_page([]))
    poller._poll_server(srv)

    status = poller._get_status('srv1')
    assert status['connected'] is True
    assert 'nodes' not in status
