"""Tests for unifi_api.py — bulk patch retry, concurrency, verification."""

import threading
import time
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
import requests

from unifi_api import UniFiAPI


def _make_http_error(status_code, body='error'):
    """Build a real requests.HTTPError with a mocked response."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.text = body
    err = requests.HTTPError(response=resp)
    return err


@pytest.fixture
def api():
    """Create a UniFiAPI with a mocked DB (skips _resolve_config)."""
    mock_db = MagicMock()
    mock_db.get_config = MagicMock(return_value=None)
    mock_db.set_config = MagicMock()
    with patch.object(UniFiAPI, '_resolve_config'):
        uapi = UniFiAPI(mock_db)
    uapi.host = 'https://fake-controller'
    uapi.api_key = 'test-key'
    uapi.enabled = True
    uapi._site_uuid = 'fake-site-uuid'
    # Pre-init session so _get_session() doesn't try real HTTP
    uapi._session = MagicMock()
    return uapi


# ── _patch_one_policy ────────────────────────────────────────────────────────


class TestPatchOnePolicy:
    def test_success(self, api):
        api.patch_firewall_policy = MagicMock(return_value={'id': 'p1'})
        result = api._patch_one_policy('p1', True)
        assert result['status'] == 'success'
        assert result['retried'] == 0
        api.patch_firewall_policy.assert_called_once_with('p1', True)

    @patch('unifi_api.time.sleep')
    def test_retry_on_429(self, mock_sleep, api):
        """429 on first attempt should retry, succeed on second."""
        api.patch_firewall_policy = MagicMock(
            side_effect=[_make_http_error(429), {'id': 'p1'}]
        )
        result = api._patch_one_policy('p1', True)
        assert result['status'] == 'success'
        assert result['retried'] == 1
        assert api.patch_firewall_policy.call_count == 2
        mock_sleep.assert_called_once_with(0.5)

    @patch('unifi_api.time.sleep')
    def test_retry_on_502(self, mock_sleep, api):
        """502 on first two attempts, succeed on third."""
        api.patch_firewall_policy = MagicMock(
            side_effect=[_make_http_error(502), _make_http_error(502), {'id': 'p1'}]
        )
        result = api._patch_one_policy('p1', False)
        assert result['status'] == 'success'
        assert result['retried'] == 2
        assert api.patch_firewall_policy.call_count == 3
        # Backoff: 0.5s, 1.0s
        assert mock_sleep.call_count == 2

    @patch('unifi_api.time.sleep')
    def test_exhausted_retries_on_429(self, mock_sleep, api):
        """Three 429s in a row should exhaust retries and fail."""
        api.patch_firewall_policy = MagicMock(
            side_effect=[_make_http_error(429), _make_http_error(429), _make_http_error(429)]
        )
        result = api._patch_one_policy('p1', True)
        assert result['status'] == 'failed'
        assert result['id'] == 'p1'
        assert 'HTTP 429' in result['error']
        # Only 2 retries (first attempt is not a retry)
        assert result['retried'] == 2

    def test_non_retryable_http_error(self, api):
        """A 400 should fail immediately without retry."""
        api.patch_firewall_policy = MagicMock(
            side_effect=_make_http_error(400, 'bad request')
        )
        result = api._patch_one_policy('p1', True)
        assert result['status'] == 'failed'
        assert 'HTTP 400' in result['error']
        assert result['retried'] == 0
        api.patch_firewall_policy.assert_called_once()

    def test_non_http_exception(self, api):
        """Connection errors and other exceptions should fail immediately."""
        api.patch_firewall_policy = MagicMock(
            side_effect=ConnectionError('refused')
        )
        result = api._patch_one_policy('p1', True)
        assert result['status'] == 'failed'
        assert 'refused' in result['error']
        assert result['retried'] == 0


# ── bulk_patch_logging ───────────────────────────────────────────────────────


class TestBulkPatchLogging:
    def test_all_succeed(self, api):
        """All policies patch successfully → success count matches."""
        api.patch_firewall_policy = MagicMock(return_value={})
        api.get_firewall_policies = MagicMock(return_value=[
            {'id': 'p1', 'loggingEnabled': True},
            {'id': 'p2', 'loggingEnabled': True},
            {'id': 'p3', 'loggingEnabled': True},
        ])

        updates = [
            {'id': 'p1', 'loggingEnabled': True},
            {'id': 'p2', 'loggingEnabled': True},
            {'id': 'p3', 'loggingEnabled': True},
        ]
        result = api.bulk_patch_logging(updates)

        assert result['total'] == 3
        assert result['success'] == 3
        assert result['failed'] == 0
        assert result['skipped'] == 0
        assert result['errors'] == []

    def test_skips_none_logging(self, api):
        """Items with loggingEnabled=None should be skipped, not patched."""
        api.patch_firewall_policy = MagicMock(return_value={})
        api.get_firewall_policies = MagicMock(return_value=[
            {'id': 'p1', 'loggingEnabled': True},
        ])

        updates = [
            {'id': 'p1', 'loggingEnabled': True},
            {'id': 'p2'},  # no loggingEnabled key
            {'id': 'p3', 'loggingEnabled': None},
        ]
        result = api.bulk_patch_logging(updates)

        assert result['total'] == 3
        assert result['success'] == 1
        assert result['skipped'] == 2
        # Only p1 should have been patched
        api.patch_firewall_policy.assert_called_once()

    def test_mixed_success_and_failure(self, api):
        """Some patches fail, others succeed — counts are correct."""
        call_count = 0
        def mock_patch(pid, val):
            nonlocal call_count
            call_count += 1
            if pid == 'p2':
                raise _make_http_error(400, 'invalid')
            return {}

        api.patch_firewall_policy = mock_patch
        api.get_firewall_policies = MagicMock(return_value=[
            {'id': 'p1', 'loggingEnabled': True},
            {'id': 'p3', 'loggingEnabled': True},
        ])

        updates = [
            {'id': 'p1', 'loggingEnabled': True},
            {'id': 'p2', 'loggingEnabled': True},
            {'id': 'p3', 'loggingEnabled': True},
        ]
        result = api.bulk_patch_logging(updates)

        assert result['success'] == 2
        assert result['failed'] == 1
        assert len(result['errors']) == 1
        assert result['errors'][0]['id'] == 'p2'

    def test_verification_detects_mismatch(self, api):
        """Verification catches policies that report success but didn't actually apply."""
        api.patch_firewall_policy = MagicMock(return_value={})
        # Controller returns loggingEnabled=False for p2 even though patch "succeeded"
        api.get_firewall_policies = MagicMock(return_value=[
            {'id': 'p1', 'loggingEnabled': True},
            {'id': 'p2', 'loggingEnabled': False},
        ])

        updates = [
            {'id': 'p1', 'loggingEnabled': True},
            {'id': 'p2', 'loggingEnabled': True},
        ]
        result = api.bulk_patch_logging(updates)

        # p2 patched "successfully" but verification caught the mismatch
        assert result['success'] == 1
        assert result['failed'] == 1
        assert any('verification' in e for e in result['errors'])

    def test_verification_does_not_double_count_patch_failures(self, api):
        """A policy that failed during patching should NOT be re-counted as a verification failure."""
        def mock_patch(pid, val):
            if pid == 'p2':
                raise _make_http_error(500, 'server error')
            return {}

        api.patch_firewall_policy = mock_patch
        # p2 still shows old state (loggingEnabled=False) since patch failed
        api.get_firewall_policies = MagicMock(return_value=[
            {'id': 'p1', 'loggingEnabled': True},
            {'id': 'p2', 'loggingEnabled': False},
        ])

        updates = [
            {'id': 'p1', 'loggingEnabled': True},
            {'id': 'p2', 'loggingEnabled': True},
        ]
        result = api.bulk_patch_logging(updates)

        # p2 should only be counted once as a patch failure, not double-counted
        assert result['failed'] == 1
        assert result['success'] == 1

    def test_verification_failure_is_graceful(self, api):
        """If get_firewall_policies raises during verification, it's logged but doesn't crash."""
        api.patch_firewall_policy = MagicMock(return_value={})
        api.get_firewall_policies = MagicMock(side_effect=ConnectionError('timeout'))

        updates = [{'id': 'p1', 'loggingEnabled': True}]
        result = api.bulk_patch_logging(updates)

        # Patch itself succeeded
        assert result['success'] == 1
        # Verification error is appended but doesn't change success count
        assert any('verification' in e for e in result['errors'])
        assert 'timeout' in result['errors'][0]['verification']

    def test_progress_callback_called(self, api):
        """progress_callback receives incremental updates during patching."""
        api.patch_firewall_policy = MagicMock(return_value={})
        api.get_firewall_policies = MagicMock(return_value=[
            {'id': 'p1', 'loggingEnabled': True},
            {'id': 'p2', 'loggingEnabled': True},
        ])

        progress_events = []
        def on_progress(completed, total, success, failed, phase='patching'):
            progress_events.append({
                'completed': completed, 'total': total,
                'success': success, 'failed': failed, 'phase': phase,
            })

        updates = [
            {'id': 'p1', 'loggingEnabled': True},
            {'id': 'p2', 'loggingEnabled': True},
        ]
        api.bulk_patch_logging(updates, progress_callback=on_progress)

        # At least 2 patching events + 1 verifying event
        patching_events = [e for e in progress_events if e['phase'] == 'patching']
        verifying_events = [e for e in progress_events if e['phase'] == 'verifying']
        assert len(patching_events) == 2
        assert len(verifying_events) == 1
        # Final patching event should show completed == total
        assert patching_events[-1]['completed'] == 2
        assert patching_events[-1]['total'] == 2

    def test_progress_callback_exception_does_not_crash(self, api):
        """A broken progress_callback should not prevent bulk_patch from completing."""
        api.patch_firewall_policy = MagicMock(return_value={})
        api.get_firewall_policies = MagicMock(return_value=[
            {'id': 'p1', 'loggingEnabled': True},
        ])

        def bad_callback(*args, **kwargs):
            raise RuntimeError('callback crashed')

        updates = [{'id': 'p1', 'loggingEnabled': True}]
        result = api.bulk_patch_logging(updates, progress_callback=bad_callback)

        # Should still complete successfully despite callback explosions
        assert result['success'] == 1
        assert result['failed'] == 0

    def test_concurrency_actually_parallel(self, api):
        """Verify that 4 workers actually run concurrently, not sequentially."""
        # Track concurrent execution with threading primitives
        max_concurrent = 0
        current_concurrent = 0
        lock = threading.Lock()

        def slow_patch(pid, val):
            nonlocal max_concurrent, current_concurrent
            with lock:
                current_concurrent += 1
                max_concurrent = max(max_concurrent, current_concurrent)
            time.sleep(0.05)  # simulate controller latency
            with lock:
                current_concurrent -= 1
            return {}

        api.patch_firewall_policy = slow_patch
        api.get_firewall_policies = MagicMock(return_value=[
            {'id': f'p{i}', 'loggingEnabled': True} for i in range(8)
        ])

        updates = [{'id': f'p{i}', 'loggingEnabled': True} for i in range(8)]
        result = api.bulk_patch_logging(updates)

        assert result['success'] == 8
        # With 4 workers and 8 items, we should see >1 concurrent execution
        assert max_concurrent > 1, f"Expected parallel execution but max_concurrent={max_concurrent}"

    def test_empty_updates(self, api):
        """Empty update list should return immediately with zero counts."""
        api.get_firewall_policies = MagicMock()
        result = api.bulk_patch_logging([])

        assert result['total'] == 0
        assert result['success'] == 0
        assert result['failed'] == 0
        assert result['skipped'] == 0
        # Should NOT call get_firewall_policies (no verification needed)
        api.get_firewall_policies.assert_not_called()

    @patch('unifi_api.time.sleep')
    def test_retried_count_aggregated(self, mock_sleep, api):
        """The retried counter in the result should sum retries across all policies."""
        call_counts = {}
        def mock_patch(pid, val):
            call_counts[pid] = call_counts.get(pid, 0) + 1
            if call_counts[pid] == 1:
                raise _make_http_error(429)
            return {}

        api.patch_firewall_policy = mock_patch
        api.get_firewall_policies = MagicMock(return_value=[
            {'id': 'p1', 'loggingEnabled': True},
            {'id': 'p2', 'loggingEnabled': True},
        ])

        updates = [
            {'id': 'p1', 'loggingEnabled': True},
            {'id': 'p2', 'loggingEnabled': True},
        ]
        result = api.bulk_patch_logging(updates)

        assert result['success'] == 2
        assert result['retried'] == 2  # each policy retried once

    def test_verification_entry_survives_error_cap(self, api):
        """25 patch failures fill the 20-entry cap; the verification entry is kept after it."""
        def mock_patch(pid, val):
            if pid.startswith('bad'):
                raise _make_http_error(500, 'server error')
            return {}

        api.patch_firewall_policy = mock_patch
        # 'ok' patched "successfully" but the controller still reports the old state
        api.get_firewall_policies = MagicMock(return_value=[{'id': 'ok', 'loggingEnabled': False}])

        updates = [{'id': f'bad{i}', 'loggingEnabled': True} for i in range(25)]
        updates.append({'id': 'ok', 'loggingEnabled': True})
        result = api.bulk_patch_logging(updates)

        assert result['failed'] == 26
        assert result['success'] == 0
        assert len(result['errors']) == 21
        assert all('id' in e and 'error' in e for e in result['errors'][:20])
        assert result['errors'][20]['verification'] == '1 policies did not reflect the requested state'
        assert result['errors'][20]['ids'] == ['ok']

    def test_verification_ignores_idless_policies(self, api):
        """An id-less policy in the verification fetch (#112) must not abort verification."""
        api.patch_firewall_policy = MagicMock(return_value={})
        api.get_firewall_policies = MagicMock(return_value=[
            {'name': 'Legacy rule', 'loggingEnabled': False},
            {'id': 'p1', 'loggingEnabled': True},
        ])

        result = api.bulk_patch_logging([{'id': 'p1', 'loggingEnabled': True}])

        assert result['success'] == 1
        assert result['failed'] == 0
        assert result['errors'] == []


# ── get_firewall_data: id-less policies (#112) ───────────────────────────────


class TestGetFirewallDataIdless:
    POLICIES = [
        {'id': 'p1', 'name': 'Allow LAN', 'loggingEnabled': True},
        {'name': 'Legacy rule', 'loggingEnabled': False},
        {'id': '', 'name': 'Empty id', 'loggingEnabled': True},
    ]

    def _setup(self, api, policies):
        api.get_firewall_policies = MagicMock(return_value=[dict(p) for p in policies])
        api.get_firewall_zones = MagicMock(return_value=[])

    def test_get_firewall_data_keeps_idless_policies(self, api, caplog):
        """Option A (#112): id-less policies stay visible and are counted."""
        self._setup(api, self.POLICIES)
        with caplog.at_level('WARNING', logger='unifi_api'):
            data = api.get_firewall_data()

        assert [p.get('name') for p in data['policies']] == ['Allow LAN', 'Legacy rule', 'Empty id']
        assert data['totalCount'] == 3
        assert data['loggingEnabled'] == 2
        assert data['loggingDisabled'] == 1
        warnings = [r for r in caplog.records if 'without an id' in r.getMessage()]
        assert len(warnings) == 1
        assert '2 firewall policies' in warnings[0].getMessage()
        assert 'hidden' not in warnings[0].getMessage()

    def test_warns_once_per_distinct_idless_set(self, api, caplog):
        self._setup(api, self.POLICIES)
        with caplog.at_level('WARNING', logger='unifi_api'):
            api.get_firewall_data()
            api.get_firewall_data()
            self._setup(api, self.POLICIES[:2])
            api.get_firewall_data()

        warnings = [r for r in caplog.records if 'without an id' in r.getMessage()]
        assert len(warnings) == 2

    def test_no_warning_without_idless_policies(self, api, caplog):
        self._setup(api, self.POLICIES[:1])
        with caplog.at_level('WARNING', logger='unifi_api'):
            data = api.get_firewall_data()

        assert data['totalCount'] == 1
        assert not [r for r in caplog.records if 'without an id' in r.getMessage()]


# ── Gateway device selection (issue #147) ────────────────────────────────────

from unifi_api import _select_gateway_device  # noqa: E402


class TestSelectGatewayDevice:
    """An Express adopted in AP mode must not be mistaken for the gateway."""

    PUBLIC_IP = '203.0.113.10'
    GW_IPS = {'192.168.178.1', '10.10.20.1'}

    def _express_ap(self, name='Express 7 - 3D', ip='192.168.178.21'):
        return {'mac': 'aa:aa', 'device_type': 'uxg', 'device_name': name,
                'ip': ip, 'state': 1}

    def _ucg_fiber(self):
        return {'mac': 'bb:bb', 'device_type': 'udm', 'device_name': 'UCG-Fiber',
                'ip': self.PUBLIC_IP, 'lan_ip': '192.168.178.1',
                'wan_ips': [self.PUBLIC_IP], 'state': 1}

    def test_express_ap_listed_first_is_not_chosen(self):
        devices = [self._express_ap(), self._express_ap('Express 7 - EG', '192.168.178.22'),
                   self._ucg_fiber()]
        gw = _select_gateway_device(devices, wan_ips={self.PUBLIC_IP},
                                    gateway_ips=self.GW_IPS)
        assert gw['device_name'] == 'UCG-Fiber'

    def test_gateway_ip_match_without_wan_info(self):
        gw_dev = {'mac': 'cc', 'device_type': 'udm', 'device_name': 'GW',
                  'ip': '192.168.178.1'}
        gw = _select_gateway_device([self._express_ap(), gw_dev],
                                    gateway_ips=self.GW_IPS)
        assert gw['device_name'] == 'GW'

    def test_raw_stat_device_wan_objects(self):
        express = {'type': 'uxg', 'name': 'Express', 'ip': '192.168.178.21',
                   'wan1': {'ip': '192.168.178.21'}}
        ucg = {'type': 'udm', 'name': 'UCG', 'ip': self.PUBLIC_IP,
               'wan1': {'ip': self.PUBLIC_IP, 'uplink_ifname': 'eth6'}}
        gw = _select_gateway_device([express, ucg], wan_ips={self.PUBLIC_IP},
                                    gateway_ips=self.GW_IPS)
        assert gw['name'] == 'UCG'

    def test_single_express_as_real_gateway_still_works(self):
        express_gw = {'mac': 'dd', 'device_type': 'uxg', 'device_name': 'Express GW',
                      'ip': self.PUBLIC_IP, 'wan_ips': [self.PUBLIC_IP]}
        gw = _select_gateway_device([express_gw], wan_ips={self.PUBLIC_IP},
                                    gateway_ips=self.GW_IPS)
        assert gw['device_name'] == 'Express GW'

    def test_no_gateway_candidates(self):
        ap = {'mac': 'ee', 'device_type': 'uap', 'device_name': 'U7', 'ip': '192.168.178.30'}
        assert _select_gateway_device([ap]) is None

    def test_fallback_without_hints_keeps_first_gateway_type(self):
        a = {'device_type': 'udm', 'device_name': 'A', 'ip': '192.168.1.1'}
        b = {'device_type': 'uxg', 'device_name': 'B', 'ip': '192.168.1.2'}
        assert _select_gateway_device([a, b])['device_name'] == 'A'


class TestPollWanIpNaming:
    """poll() must map the WAN IP to the real gateway's name (issue #147)."""

    def test_wan_ip_named_after_real_gateway(self, api):
        api.features = {'client_names': False, 'device_discovery': True,
                        'network_config': True}
        devices = [
            {'mac': 'aa', 'ip': '192.168.178.21', 'device_name': 'Express 7 - 3D',
             'device_type': 'uxg', 'state': 1, 'lan_ip': None, 'wan_ips': []},
            {'mac': 'bb', 'ip': '203.0.113.10', 'device_name': 'UCG-Fiber',
             'device_type': 'udm', 'state': 1, 'lan_ip': '192.168.178.1',
             'wan_ips': ['203.0.113.10']},
        ]
        net_config = {
            'wan_interfaces': [{'physical_interface': 'eth6', 'wan_ip': '203.0.113.10'}],
            'networks': [{'ip_subnet': '192.168.178.1/24', 'vlan': None, 'name': 'Default'}],
        }
        with patch.object(api, '_poll_devices', return_value=devices), \
             patch.object(api, 'get_network_config', return_value=net_config):
            api.poll()
        assert api._ip_to_name['203.0.113.10'] == 'UCG-Fiber'
        api._db.set_config.assert_any_call('wan_ip_names', {'203.0.113.10': 'UCG-Fiber'})


class TestSelectGatewayDeviceRealWorld:
    """Shape of a real site from issue #147 (public IPs replaced by docs ranges):
    UCG-Fiber + two Express 7 in AP mode. The Expresses report type 'udm' and
    even a wan3 object (shared 5G GRE tunnel), so neither type nor the presence
    of wan* keys identifies the gateway."""

    PUBLIC = '203.0.113.5'
    GW_IPS = {'192.168.178.1', '192.168.20.1', '192.168.30.1', '192.168.2.1',
              '10.2.0.2', '192.168.178.20'}

    def _raw(self):
        def express(name, ip):
            return {'name': name, 'model': 'UDMA69B', 'type': 'udm', 'state': 1,
                    'ip': ip, 'connect_request_ip': ip,
                    'wan3': {'ip': '10.153.249.11', 'uplink_ifname': 'gre1'},
                    'uplink': {'type': 'wire', 'uplink_mac': '8c:ed:e1:00:00:01'}}
        ucg = {'name': 'Cloud Gateway Fiber', 'model': 'UDMA6A8', 'type': 'udm',
               'state': 1, 'ip': self.PUBLIC, 'connect_request_ip': '127.0.0.1',
               'wan1': {'ip': self.PUBLIC, 'uplink_ifname': 'ppp0'},
               'wan3': {'ip': '10.153.249.11', 'uplink_ifname': 'gre1'},
               'uplink': {'type': 'wire', 'uplink_mac': None}}
        return [express('Express 7 - 3D', '192.168.178.21'),
                express('Express 7 - WZ', '192.168.178.22'), ucg]

    def test_raw_stat_device(self):
        gw = _select_gateway_device(self._raw(),
                                    wan_ips={self.PUBLIC, '198.51.100.129'},
                                    gateway_ips=self.GW_IPS)
        assert gw['name'] == 'Cloud Gateway Fiber'

    def test_without_wan_ip_hints(self):
        # Even if WAN IPs are unknown, LAN-addressed Expresses lose.
        gw = _select_gateway_device(self._raw(), gateway_ips=self.GW_IPS)
        assert gw['name'] == 'Cloud Gateway Fiber'

    def test_get_network_config_uses_real_gateway_wans(self, api):
        responses = {
            'rest/networkconf': {'data': [
                {'name': 'Internet 1', 'purpose': 'wan', 'wan_networkgroup': 'WAN',
                 'wan_type': 'pppoe'},
                {'name': 'Default', 'purpose': 'corporate',
                 'ip_subnet': '192.168.178.1/24'},
            ]},
            'stat/health': {'data': [{'subsystem': 'wan', 'wan_ip': self.PUBLIC}]},
            'stat/device': {'data': self._raw()},
        }
        with patch.object(api, '_get', side_effect=lambda p, *a, **k: responses.get(p, {'data': []})), \
             patch.object(api, '_get_integration_site', return_value={'data': []}):
            cfg = api.get_network_config()
        wan = [w for w in cfg['wan_interfaces'] if w['name'] == 'Internet 1'][0]
        assert wan['detected_from'] == 'device'  # not the static fallback map
        assert wan['physical_interface'] == 'ppp0'
        assert wan['wan_ip'] == self.PUBLIC
