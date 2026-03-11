"""Tests for ip_identity.py — IP annotation precedence and record mutation."""

import ipaddress
from unittest.mock import MagicMock, patch

import pytest

from ip_identity import IdentityConfig, annotate_ip, annotate_record, load_identity_config


# ── Fixtures ────────────────────────────────────────────────────────────────

def _cfg(**overrides):
    """Build an IdentityConfig with sensible defaults."""
    defaults = dict(
        gateway_vlans={},
        wan_ip_names={},
        vpn_cidrs=[],
        exclude_ips=set(),
    )
    defaults.update(overrides)
    return IdentityConfig(**defaults)


# ── annotate_ip — precedence ────────────────────────────────────────────────

class TestAnnotateIpPrecedence:
    def test_existing_name_wins_over_gateway(self):
        cfg = _cfg(gateway_vlans={'192.168.1.1': {'vlan': 10}})
        name, vlan, badge = annotate_ip(cfg, '192.168.1.1', existing_name='MyRouter')
        assert name == 'MyRouter'
        assert vlan == 10  # vlan still set even when name is preserved

    def test_gateway_sets_name_and_vlan(self):
        cfg = _cfg(gateway_vlans={'192.168.1.1': {'vlan': 20}})
        name, vlan, badge = annotate_ip(cfg, '192.168.1.1')
        assert name == 'Gateway'
        assert vlan == 20
        assert badge is None

    def test_wan_sets_name_when_no_gateway(self):
        cfg = _cfg(wan_ip_names={'203.0.113.5': 'ISP WAN'})
        name, vlan, badge = annotate_ip(cfg, '203.0.113.5')
        assert name == 'ISP WAN'
        assert vlan is None

    def test_wan_skipped_if_existing_name(self):
        cfg = _cfg(wan_ip_names={'203.0.113.5': 'ISP WAN'})
        name, vlan, badge = annotate_ip(cfg, '203.0.113.5', existing_name='CustomDevice')
        assert name == 'CustomDevice'

    def test_gateway_wins_over_wan(self):
        cfg = _cfg(
            gateway_vlans={'10.0.0.1': {'vlan': 1}},
            wan_ip_names={'10.0.0.1': 'WAN'},
        )
        name, vlan, badge = annotate_ip(cfg, '10.0.0.1')
        assert name == 'Gateway'
        assert vlan == 1

    def test_vpn_match_gateway_ip(self):
        """VPN gateway IP (.1) gets name='Gateway' + vpn badge."""
        net = ipaddress.ip_network('10.13.13.0/24')
        gw = ipaddress.ip_address('10.13.13.1')
        cfg = _cfg(vpn_cidrs=[(net, gw, 'WireGuard', 'WG Client')])
        name, vlan, badge = annotate_ip(cfg, '10.13.13.1')
        assert name == 'Gateway'
        assert badge == 'WireGuard'

    def test_vpn_match_non_gateway_ip(self):
        """Non-gateway VPN IP gets the VPN type name."""
        net = ipaddress.ip_network('10.13.13.0/24')
        gw = ipaddress.ip_address('10.13.13.1')
        cfg = _cfg(vpn_cidrs=[(net, gw, 'WireGuard', 'WG Client')])
        name, vlan, badge = annotate_ip(cfg, '10.13.13.42')
        assert name == 'WG Client'
        assert badge == 'WireGuard'

    def test_vpn_skipped_if_name_already_set(self):
        net = ipaddress.ip_network('10.13.13.0/24')
        gw = ipaddress.ip_address('10.13.13.1')
        cfg = _cfg(vpn_cidrs=[(net, gw, 'WireGuard', 'WG Client')])
        name, vlan, badge = annotate_ip(cfg, '10.13.13.42', existing_name='Phone')
        assert name == 'Phone'
        assert badge is None

    def test_vpn_skipped_if_excluded(self):
        net = ipaddress.ip_network('10.13.13.0/24')
        gw = ipaddress.ip_address('10.13.13.1')
        cfg = _cfg(
            vpn_cidrs=[(net, gw, 'WireGuard', 'WG Client')],
            exclude_ips={'10.13.13.42'},
        )
        name, vlan, badge = annotate_ip(cfg, '10.13.13.42')
        assert name is None
        assert badge is None


# ── annotate_ip — edge cases ────────────────────────────────────────────────

class TestAnnotateIpEdgeCases:
    def test_empty_ip(self):
        cfg = _cfg()
        name, vlan, badge = annotate_ip(cfg, '')
        assert name is None

    def test_ip_with_cidr_suffix_stripped(self):
        cfg = _cfg(gateway_vlans={'10.0.0.1': {'vlan': 5}})
        name, vlan, badge = annotate_ip(cfg, '10.0.0.1/32')
        assert name == 'Gateway'
        assert vlan == 5

    def test_no_match_returns_all_none(self):
        cfg = _cfg()
        name, vlan, badge = annotate_ip(cfg, '8.8.8.8')
        assert name is None
        assert vlan is None
        assert badge is None

    def test_gateway_missing_vlan_key(self):
        cfg = _cfg(gateway_vlans={'10.0.0.1': {}})
        name, vlan, badge = annotate_ip(cfg, '10.0.0.1')
        assert name == 'Gateway'
        assert vlan is None  # .get('vlan') returns None

    def test_empty_vpn_cidrs_skips_matching(self):
        cfg = _cfg(vpn_cidrs=[])
        name, vlan, badge = annotate_ip(cfg, '10.13.13.42')
        assert badge is None


# ── annotate_record ─────────────────────────────────────────────────────────

class TestAnnotateRecord:
    def test_sets_src_and_dst(self):
        cfg = _cfg(
            gateway_vlans={'192.168.1.1': {'vlan': 10}},
            wan_ip_names={'203.0.113.5': 'ISP WAN'},
        )
        record = {'src_ip': '192.168.1.1', 'dst_ip': '203.0.113.5'}
        annotate_record(cfg, record)
        assert record['src_device_name'] == 'Gateway'
        assert record['src_device_vlan'] == 10
        assert record['dst_device_name'] == 'ISP WAN'

    def test_skips_if_vlan_already_set(self):
        cfg = _cfg(gateway_vlans={'192.168.1.1': {'vlan': 10}})
        record = {'src_ip': '192.168.1.1', 'src_device_vlan': 99}
        annotate_record(cfg, record)
        # Should NOT overwrite — guard skips this prefix entirely
        assert record['src_device_vlan'] == 99
        assert 'src_device_name' not in record

    def test_skips_if_network_badge_already_set(self):
        cfg = _cfg(wan_ip_names={'1.2.3.4': 'WAN'})
        record = {'src_ip': '1.2.3.4', 'src_device_network': 'WireGuard'}
        annotate_record(cfg, record)
        assert 'src_device_name' not in record

    def test_preserves_existing_device_name(self):
        cfg = _cfg(wan_ip_names={'1.2.3.4': 'WAN'})
        record = {'src_ip': '1.2.3.4', 'src_device_name': 'CustomDevice'}
        annotate_record(cfg, record)
        # existing name wins, WAN name NOT applied
        assert record['src_device_name'] == 'CustomDevice'

    def test_vpn_gateway_sets_network_badge(self):
        net = ipaddress.ip_network('10.13.13.0/24')
        gw = ipaddress.ip_address('10.13.13.1')
        cfg = _cfg(vpn_cidrs=[(net, gw, 'WireGuard', 'WG Client')])
        record = {'src_ip': '10.13.13.1', 'dst_ip': '8.8.8.8'}
        annotate_record(cfg, record)
        assert record['src_device_name'] == 'Gateway'
        assert record['src_device_network'] == 'WireGuard'

    def test_vpn_non_gateway_no_network_badge(self):
        """Non-gateway VPN IPs don't get a network badge (only Gateway does)."""
        net = ipaddress.ip_network('10.13.13.0/24')
        gw = ipaddress.ip_address('10.13.13.1')
        cfg = _cfg(vpn_cidrs=[(net, gw, 'WireGuard', 'WG Client')])
        record = {'src_ip': '10.13.13.42', 'dst_ip': '8.8.8.8'}
        annotate_record(cfg, record)
        assert record['src_device_name'] == 'WG Client'
        assert 'src_device_network' not in record

    def test_none_ip_handled(self):
        cfg = _cfg()
        record = {'src_ip': None, 'dst_ip': None}
        annotate_record(cfg, record)  # Should not raise


# ── load_identity_config ────────────────────────────────────────────────────

class TestLoadIdentityConfig:
    @patch('ip_identity.build_vpn_cidr_map')
    @patch('ip_identity.get_config')
    def test_loads_all_configs(self, mock_get_config, mock_build_vpn):
        mock_get_config.side_effect = lambda db, key: {
            'gateway_ip_vlans': {'192.168.1.1': {'vlan': 10}},
            'wan_ip_names': {'203.0.113.5': 'ISP WAN'},
            'vpn_networks': {'wg0': {'cidr': '10.13.13.0/24'}},
        }.get(key)
        mock_build_vpn.return_value = [('fake_cidr_tuple',)]

        cfg = load_identity_config(MagicMock())

        assert '192.168.1.1' in cfg.gateway_vlans
        assert '203.0.113.5' in cfg.wan_ip_names
        assert len(cfg.vpn_cidrs) == 1
        assert cfg.exclude_ips == {'192.168.1.1', '203.0.113.5'}

    @patch('ip_identity.build_vpn_cidr_map')
    @patch('ip_identity.get_config')
    def test_empty_configs(self, mock_get_config, mock_build_vpn):
        mock_get_config.return_value = None
        cfg = load_identity_config(MagicMock())

        assert cfg.gateway_vlans == {}
        assert cfg.wan_ip_names == {}
        assert cfg.vpn_cidrs == []
        assert cfg.exclude_ips == set()
        mock_build_vpn.assert_not_called()
