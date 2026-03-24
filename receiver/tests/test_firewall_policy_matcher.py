"""Tests for firewall_policy_matcher.py — rule parsing, zone map, matching, and caching."""

import time
from unittest.mock import MagicMock, patch

import pytest

import firewall_policy_matcher as fpm


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clear_cache():
    """Ensure each test starts with a clean cache."""
    fpm.invalidate_cache()
    yield
    fpm.invalidate_cache()


def _make_api(zones=None, networks=None, net_config=None, policies=None):
    """Build a mock unifi_api with controllable return data."""
    api = MagicMock()
    api.get_firewall_zones.return_value = zones or []
    # Networks are delivered via get_network_config()['networks']
    base_net_config = net_config or {'wan_interfaces': []}
    if networks:
        base_net_config.setdefault('networks', []).extend(networks)
    elif 'networks' not in base_net_config:
        base_net_config['networks'] = []
    api.get_network_config.return_value = base_net_config
    api.get_firewall_data.return_value = {
        'policies': policies or [],
        'zones': zones or [],
        'totalCount': len(policies) if policies else 0,
    }
    return api


def _zone(zone_id, name, network_ids=None, origin='SYSTEM_DEFINED'):
    return {
        'id': zone_id,
        'name': name,
        'networkIds': network_ids or [],
        'metadata': {'origin': origin},
    }


def _network(net_id, name, vlan_id):
    iface = 'br0' if vlan_id == 1 else f'br{vlan_id}'
    return {'id': net_id, 'name': name, 'interface': iface, 'vlan': vlan_id}


def _policy(policy_id, name, src_zone, dst_zone, action, index,
            logging=False, origin='USER_DEFINED', enabled=True):
    return {
        'id': policy_id,
        'name': name,
        'source': {'zoneId': src_zone},
        'destination': {'zoneId': dst_zone},
        'action': {'type': action},
        'index': index,
        'loggingEnabled': logging,
        'enabled': enabled,
        'metadata': {'origin': origin},
    }


# ── parse_rule_name ──────────────────────────────────────────────────────────

class TestParseRuleName:
    def test_standard_allow(self):
        result = fpm.parse_rule_name('WAN_LOCAL-A-100')
        assert result == {'chain': 'WAN_LOCAL', 'action_code': 'A', 'index': 100}

    def test_standard_drop(self):
        result = fpm.parse_rule_name('LAN_WAN-D-2147483647')
        assert result == {'chain': 'LAN_WAN', 'action_code': 'D', 'index': 2147483647}

    def test_reject(self):
        result = fpm.parse_rule_name('WAN_LOCAL-R-50')
        assert result == {'chain': 'WAN_LOCAL', 'action_code': 'R', 'index': 50}

    def test_custom_chain(self):
        result = fpm.parse_rule_name('CUSTOM2_WAN-A-2147483647')
        assert result == {'chain': 'CUSTOM2_WAN', 'action_code': 'A', 'index': 2147483647}

    def test_none_input(self):
        assert fpm.parse_rule_name(None) is None

    def test_empty_string(self):
        assert fpm.parse_rule_name('') is None

    def test_invalid_format(self):
        assert fpm.parse_rule_name('no-match-here') is None

    def test_unrecognized_action_code(self):
        assert fpm.parse_rule_name('WAN_LOCAL-X-100') is None

    def test_missing_index(self):
        assert fpm.parse_rule_name('WAN_LOCAL-A-') is None


# ── build_zone_map ───────────────────────────────────────────────────────────

class TestBuildZoneMap:
    def test_basic_lan_zone(self):
        api = _make_api(
            zones=[_zone('z1', 'Internal', ['net1'])],
            networks=[_network('net1', 'Default', 1)],
        )
        result = fpm.build_zone_map(api)
        zm = result['zone_map']
        assert len(zm) == 1
        assert zm[0]['zone_id'] == 'z1'
        assert zm[0]['chain_name'] == 'LAN'
        assert zm[0]['interfaces'][0]['interface'] == 'br0'

    def test_vlan_interface(self):
        api = _make_api(
            zones=[_zone('z1', 'Internal', ['net1'])],
            networks=[_network('net1', 'IoT', 50)],
        )
        result = fpm.build_zone_map(api)
        assert result['zone_map'][0]['interfaces'][0]['interface'] == 'br50'

    def test_external_zone_wan(self):
        api = _make_api(
            zones=[_zone('z2', 'External')],
            net_config={'wan_interfaces': [
                {'name': 'WAN', 'physical_interface': 'eth3', 'active': True, 'wan_ip': '1.2.3.4'},
            ]},
        )
        result = fpm.build_zone_map(api)
        ifaces = result['zone_map'][0]['interfaces']
        assert len(ifaces) == 1
        assert ifaces[0]['interface'] == 'eth3'

    def test_gateway_zone_no_interfaces(self):
        api = _make_api(zones=[_zone('z3', 'Gateway')])
        result = fpm.build_zone_map(api)
        assert result['zone_map'][0]['interfaces'] == []
        assert result['zone_map'][0]['chain_name'] == 'LOCAL'

    def test_vpn_zone(self):
        api = _make_api(zones=[_zone('z4', 'VPN')])
        vpn = {'wg0': {'badge': 'WireGuard', 'cidr': '10.0.0.0/24'}}
        result = fpm.build_zone_map(api, vpn_networks=vpn)
        ifaces = result['zone_map'][0]['interfaces']
        assert len(ifaces) == 1
        assert ifaces[0]['interface'] == 'wg0'
        assert ifaces[0]['vpn'] is True

    def test_custom_zone_chain_name(self):
        api = _make_api(zones=[_zone('z5', 'SmartHome')])
        result = fpm.build_zone_map(api)
        assert result['zone_map'][0]['chain_name'] == 'CUSTOM1'

    def test_missing_network_id_graceful(self):
        # Zone references a network ID not present in net_config
        api = _make_api(zones=[_zone('z1', 'Internal', ['net-missing'])])
        result = fpm.build_zone_map(api)
        # Should succeed with no interfaces (graceful degradation)
        assert result['zone_map'][0]['interfaces'] == []


# ── match_log_to_policy ──────────────────────────────────────────────────────

class TestMatchLogToPolicy:
    def _setup_match(self, policies=None, extra_zones=None):
        """Standard 3-zone setup: Internal(br0), External(eth3), Gateway(no ifaces)."""
        zones = [
            _zone('z-int', 'Internal', ['net-default']),
            _zone('z-ext', 'External'),
            _zone('z-gw', 'Gateway'),
        ]
        if extra_zones:
            zones.extend(extra_zones)
        networks = [_network('net-default', 'Default', 1)]
        net_config = {'wan_interfaces': [
            {'name': 'WAN', 'physical_interface': 'eth3', 'active': True},
        ]}
        api = _make_api(
            zones=zones,
            networks=networks,
            net_config=net_config,
            policies=policies or [],
        )
        return api

    def test_matched_single_policy(self):
        policies = [_policy('p1', 'Block IoT', 'z-int', 'z-ext', 'BLOCK', 100, logging=True)]
        api = self._setup_match(policies)
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        assert result['status'] == 'matched'
        assert result['policy']['id'] == 'p1'
        assert result['policy']['loggingEnabled'] is True

    def test_unmatched_no_policy(self):
        api = self._setup_match(policies=[])
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        assert result['status'] == 'unmatched'

    def test_unmatched_wrong_index(self):
        policies = [_policy('p1', 'Block IoT', 'z-int', 'z-ext', 'BLOCK', 200)]
        api = self._setup_match(policies)
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        assert result['status'] == 'unmatched'

    def test_unmatched_wrong_action(self):
        policies = [_policy('p1', 'Allow All', 'z-int', 'z-ext', 'ALLOW', 100)]
        api = self._setup_match(policies)
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        assert result['status'] == 'unmatched'

    def test_gateway_zone_empty_interface_out(self):
        """Falsy interface_out maps to Gateway zone."""
        policies = [_policy('p1', 'Block to GW', 'z-int', 'z-gw', 'BLOCK', 50)]
        api = self._setup_match(policies)
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='',
            rule_name='LAN_LOCAL-D-50',
        )
        assert result['status'] == 'matched'
        assert result['policy']['id'] == 'p1'

    def test_uncontrollable_derived(self):
        policies = [_policy('p1', 'Auto Rule', 'z-int', 'z-ext', 'BLOCK', 100,
                            origin='DERIVED')]
        api = self._setup_match(policies)
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        assert result['status'] == 'uncontrollable'
        assert 'auto-generated' in result['message']

    def test_uncontrollable_disabled(self):
        policies = [_policy('p1', 'Disabled Rule', 'z-int', 'z-ext', 'BLOCK', 100,
                            enabled=False)]
        api = self._setup_match(policies)
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        assert result['status'] == 'uncontrollable'
        assert 'disabled' in result['message']

    def test_controllable_with_derived_twin(self):
        """DERIVED twin should be filtered out, leaving one controllable match."""
        policies = [
            _policy('p1', 'User Rule', 'z-int', 'z-ext', 'BLOCK', 100, origin='USER_DEFINED'),
            _policy('p2', 'Auto Rule', 'z-int', 'z-ext', 'BLOCK', 100, origin='DERIVED'),
        ]
        api = self._setup_match(policies)
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        assert result['status'] == 'matched'
        assert result['policy']['id'] == 'p1'

    def test_ambiguous_two_controllable(self):
        policies = [
            _policy('p1', 'Rule A', 'z-int', 'z-ext', 'BLOCK', 100),
            _policy('p2', 'Rule B', 'z-int', 'z-ext', 'BLOCK', 100),
        ]
        api = self._setup_match(policies)
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        assert result['status'] == 'ambiguous'

    def test_unsupported_reject(self):
        api = self._setup_match()
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-R-100',
        )
        assert result['status'] == 'unsupported'
        assert 'Reject' in result['message']

    def test_unsupported_unparseable_rule(self):
        api = self._setup_match()
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='garbage',
        )
        assert result['status'] == 'unsupported'

    def test_unknown_interface_in(self):
        api = self._setup_match()
        result = fpm.match_log_to_policy(
            api, interface_in='br999', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        assert result['status'] == 'unmatched'
        assert 'Unknown source interface' in result['message']

    def test_unknown_interface_out(self):
        api = self._setup_match()
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth99',
            rule_name='LAN_WAN-D-100',
        )
        assert result['status'] == 'unmatched'
        assert 'Unknown destination interface' in result['message']

    def test_error_on_api_failure(self):
        api = self._setup_match()
        api.get_firewall_data.side_effect = Exception('connection refused')
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        assert result['status'] == 'error'

    def test_origin_flat_in_response(self):
        """origin should be a flat field in the policy response, not nested in metadata."""
        policies = [_policy('p1', 'Test', 'z-int', 'z-ext', 'ALLOW', 50,
                            origin='USER_DEFINED')]
        api = self._setup_match(policies)
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-A-50',
        )
        assert result['policy']['origin'] == 'USER_DEFINED'
        assert 'metadata' not in result['policy']


# ── Snapshot cache ───────────────────────────────────────────────────────────

class TestSnapshotCache:
    def _setup(self):
        policies = [_policy('p1', 'Test', 'z-int', 'z-ext', 'BLOCK', 100)]
        zones = [
            _zone('z-int', 'Internal', ['net1']),
            _zone('z-ext', 'External'),
            _zone('z-gw', 'Gateway'),
        ]
        networks = [_network('net1', 'Default', 1)]
        net_config = {'wan_interfaces': [
            {'name': 'WAN', 'physical_interface': 'eth3', 'active': True},
        ]}
        api = _make_api(zones=zones, networks=networks, net_config=net_config, policies=policies)
        return api

    def test_cache_hit(self):
        api = self._setup()
        # First call populates cache
        fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        call_count = api.get_firewall_data.call_count

        # Second call should hit cache
        fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        assert api.get_firewall_data.call_count == call_count

    def test_cache_invalidation(self):
        api = self._setup()
        fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        call_count = api.get_firewall_data.call_count

        fpm.invalidate_cache()

        fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        assert api.get_firewall_data.call_count == call_count + 1

    def test_cache_expiry(self):
        api = self._setup()
        fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        call_count = api.get_firewall_data.call_count

        # Manually expire the cache
        with fpm._cache_lock:
            fpm._cached_snapshot['expires_at'] = time.monotonic() - 1

        fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        assert api.get_firewall_data.call_count == call_count + 1

    def test_cache_ttl_is_5_minutes(self):
        assert fpm._CACHE_TTL == 300
