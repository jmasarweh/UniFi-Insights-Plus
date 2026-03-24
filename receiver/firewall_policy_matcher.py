"""Firewall policy matcher — zone map building, snapshot caching, and log-to-policy matching.

This module is the single home for:
- Building the interface-to-zone map from raw UniFi API data
- Matching a firewall log entry to a policy candidate
- 5-minute snapshot caching with invalidation

It calls unifi_api for raw data but owns all derived/enrichment logic.
unifi_api.py must NOT contain any of this.
"""

import logging
import re
import time
import threading

logger = logging.getLogger('api.firewall_matcher')

# ── Zone chain name mapping (iptables convention) ────────────────────────────

_ZONE_CHAIN_MAP = {
    'internal': 'LAN',
    'external': 'WAN',
    'gateway': 'LOCAL',
    'hotspot': 'GUEST',
    'vpn': 'VPN',
    'dmz': 'DMZ',
}

# ── Rule name parsing ────────────────────────────────────────────────────────

_RULE_NAME_RE = re.compile(r'^(.+?)-(A|D|R)-(\d+)$')

_ACTION_CODE_TO_POLICY = {'A': 'ALLOW', 'D': 'BLOCK'}


def parse_rule_name(rule_name):
    """Parse a syslog rule_name into (chain, action_code, index) or None."""
    if not rule_name:
        return None
    m = _RULE_NAME_RE.match(rule_name)
    if not m:
        return None
    return {
        'chain': m.group(1),
        'action_code': m.group(2),
        'index': int(m.group(3)),
    }


# ── Snapshot cache ───────────────────────────────────────────────────────────
# Scoped to log-to-policy matching only.  GET /api/firewall/policies (the
# FirewallRules matrix) intentionally bypasses this cache and fetches live
# data — users managing policies need real-time state.

_CACHE_TTL = 300  # 5 minutes

_cache_lock = threading.Lock()
_cached_snapshot = None  # {'zone_data': ..., 'policies': ..., 'expires_at': float}


def invalidate_cache():
    """Invalidate the firewall snapshot cache.

    Called after successful PATCH, bulk logging, SSE completion, or settings reload.
    """
    global _cached_snapshot
    with _cache_lock:
        _cached_snapshot = None
    logger.debug("Firewall snapshot cache invalidated")


def _get_snapshot(unifi_api, vpn_networks=None):
    """Return cached snapshot or build a fresh one.

    Thread-safe. The snapshot contains zone_data (zone map) and policies
    (raw firewall data from the Integration API). TTL is 5 minutes.
    """
    global _cached_snapshot

    with _cache_lock:
        if _cached_snapshot and time.monotonic() < _cached_snapshot['expires_at']:
            return _cached_snapshot

    # Build outside the lock to avoid blocking other threads during API calls.
    # Multiple threads may race to build; the last write wins (safe — all produce
    # equivalent data from the same UniFi state).
    zone_data = build_zone_map(unifi_api, vpn_networks=vpn_networks)
    fw_data = unifi_api.get_firewall_data()

    snapshot = {
        'zone_data': zone_data,
        'policies': fw_data.get('policies', []),
        'zones': fw_data.get('zones', []),
        'expires_at': time.monotonic() + _CACHE_TTL,
    }

    with _cache_lock:
        _cached_snapshot = snapshot

    logger.debug("Firewall snapshot cache refreshed (%d policies, %d zones)",
                 len(snapshot['policies']), len(snapshot['zones']))
    return snapshot


# ── Zone map builder ─────────────────────────────────────────────────────────

def build_zone_map(unifi_api, vpn_networks=None):
    """Build zone-to-interface mapping by combining zones, networks, and WAN config.

    Calls raw unifi_api methods for data, then assembles the derived mapping.

    Args:
        unifi_api: UniFiAPI instance (raw data access only).
        vpn_networks: dict of {interface: label_or_dict} from system_config.

    Returns:
        dict with 'zone_map', 'wan_interfaces', 'vpn_interfaces'.
    """
    if vpn_networks is None:
        vpn_networks = {}

    zones = unifi_api.get_firewall_zones()
    net_config = unifi_api.get_network_config()

    # Build network_id -> interface from get_network_config() networks
    network_id_to_info = {}
    for net in net_config.get('networks', []):
        nid = net.get('id')
        if not nid:
            continue
        network_id_to_info[nid] = {
            'name': net.get('name', ''),
            'interface': net.get('interface'),
            'vlan': net.get('vlan'),
        }

    # WAN physical interfaces
    wan_interfaces = []
    for w in net_config.get('wan_interfaces', []):
        wan_interfaces.append({
            'name': w['name'],
            'interface': w['physical_interface'],
            'active': w.get('active', False),
            'wan_ip': w.get('wan_ip'),
        })

    # Build the zone map
    zone_map = []
    custom_idx = 0
    for z in zones:
        zname = z.get('name', '')
        zname_lower = zname.lower()

        # Determine chain name
        chain = _ZONE_CHAIN_MAP.get(zname_lower)
        if chain is None:
            custom_idx += 1
            chain = f'CUSTOM{custom_idx}'

        # Resolve interfaces from networkIds
        interfaces = []
        for nid in z.get('networkIds', []):
            info = network_id_to_info.get(nid)
            if info and info.get('interface'):
                interfaces.append({
                    'interface': info['interface'],
                    'network_name': info['name'],
                    'vlan': info.get('vlan'),
                })
            elif info and info.get('purpose') == 'wan':
                for wi in wan_interfaces:
                    interfaces.append({
                        'interface': wi['interface'],
                        'network_name': wi['name'],
                        'wan_ip': wi.get('wan_ip'),
                    })

        # External zone — add WAN interfaces
        if zname_lower == 'external' and not interfaces:
            for wi in wan_interfaces:
                interfaces.append({
                    'interface': wi['interface'],
                    'network_name': wi['name'],
                    'wan_ip': wi.get('wan_ip'),
                })

        # VPN zone — add VPN interfaces
        if zname_lower == 'vpn':
            for vpn_iface, vpn_label in vpn_networks.items():
                if isinstance(vpn_label, dict):
                    name = vpn_label.get('badge', vpn_iface)
                    cidr = vpn_label.get('cidr', '')
                else:
                    name = vpn_label or vpn_iface
                    cidr = ''
                interfaces.append({
                    'interface': vpn_iface,
                    'network_name': name,
                    'vpn': True,
                    'cidr': cidr or None,
                })

        # Gateway zone has no interfaces (it's the gateway itself)

        zone_map.append({
            'zone_id': z['id'],
            'zone_name': zname,
            'chain_name': chain,
            'origin': z.get('metadata', {}).get('origin', 'UNKNOWN'),
            'interfaces': interfaces,
        })

    return {
        'zone_map': zone_map,
        'wan_interfaces': wan_interfaces,
        'vpn_interfaces': [{'interface': k, 'label': v} for k, v in vpn_networks.items()],
    }


# ── Policy matching ──────────────────────────────────────────────────────────

def match_log_to_policy(unifi_api, interface_in, interface_out, rule_name,
                        vpn_networks=None):
    """Match a firewall log entry to a single firewall policy.

    Uses the cached snapshot to avoid repeated UniFi API calls.
    The action is derived from rule_name parsing (A/D/R), not from the
    log's rule_action field, so rule_action is not needed here.

    Args:
        unifi_api: UniFiAPI instance.
        interface_in: Source interface from the log (e.g. 'br50', 'eth3').
        interface_out: Destination interface from the log (e.g. 'eth3', '' for Gateway).
        rule_name: Syslog rule_name (e.g. 'CUSTOM2_WAN-A-2147483647').
        vpn_networks: dict from system_config.

    Returns:
        dict with 'status' and optional 'policy'/'message' keys.
        Statuses: matched, unmatched, ambiguous, uncontrollable, unsupported, error.
    """
    # Parse rule_name
    parsed = parse_rule_name(rule_name)
    if not parsed:
        return {"status": "unsupported", "message": "Could not parse rule name."}

    action_code = parsed['action_code']
    rule_index = parsed['index']

    # R (reject) is unsupported until verified against live payloads
    if action_code == 'R':
        return {"status": "unsupported",
                "message": "Reject rules are not yet supported for log matching."}

    expected_action = _ACTION_CODE_TO_POLICY.get(action_code)

    # Get cached snapshot (zone map + policies)
    try:
        snapshot = _get_snapshot(unifi_api, vpn_networks=vpn_networks)
    except Exception as e:
        logger.exception("Failed to build firewall snapshot for matching")
        return {"status": "error", "message": str(e)}

    zone_data = snapshot['zone_data']

    # Build interface -> zone_id and zone_id -> zone_name lookups
    iface_to_zone = {}
    zone_id_to_name = {}
    gateway_zone_id = None
    for z in zone_data.get('zone_map', []):
        zone_id_to_name[z['zone_id']] = z['zone_name']
        if z['zone_name'].lower() == 'gateway':
            gateway_zone_id = z['zone_id']
        for iface in z['interfaces']:
            iface_to_zone[iface['interface']] = z['zone_id']

    # Resolve source zone from interface_in
    src_zone_id = iface_to_zone.get(interface_in)
    if not src_zone_id:
        return {"status": "unmatched",
                "message": f"Unknown source interface: {interface_in}"}

    # Resolve dest zone from interface_out (falsy = Gateway)
    if not interface_out:
        dst_zone_id = gateway_zone_id
    else:
        dst_zone_id = iface_to_zone.get(interface_out)
    if not dst_zone_id:
        return {"status": "unmatched",
                "message": f"Unknown destination interface: {interface_out or '(empty)'}"}

    policies = snapshot['policies']

    # Match across ALL policies first (zone pair + action + index)
    all_matches = []
    for p in policies:
        if p.get('source', {}).get('zoneId') != src_zone_id:
            continue
        if p.get('destination', {}).get('zoneId') != dst_zone_id:
            continue
        if p.get('action', {}).get('type') != expected_action:
            continue
        if p.get('index') != rule_index:
            continue
        all_matches.append(p)

    if len(all_matches) == 0:
        return {"status": "unmatched",
                "message": "No matching policy found"}

    # Build controllable candidate set — filter DERIVED and disabled BEFORE
    # deciding ambiguity, so an uncontrollable twin doesn't block a valid match.
    controllable = [p for p in all_matches
                    if p.get('metadata', {}).get('origin', '') != 'DERIVED'
                    and p.get('enabled') is not False]

    if len(controllable) == 0:
        # All matches are uncontrollable
        policy = all_matches[0]
        origin = policy.get('metadata', {}).get('origin', '')
        if origin == 'DERIVED':
            return {
                "status": "uncontrollable",
                "message": "This rule is auto-generated and cannot be modified.",
                "policy": {"id": policy['id'], "name": policy.get('name', '')}
            }
        return {
            "status": "uncontrollable",
            "message": "This rule is disabled and cannot be toggled.",
            "policy": {"id": policy['id'], "name": policy.get('name', '')}
        }

    if len(controllable) > 1:
        return {"status": "ambiguous",
                "message": "Multiple matching policies found."}

    policy = controllable[0]
    origin = policy.get('metadata', {}).get('origin', '')

    return {
        "status": "matched",
        "policy": {
            "id": policy['id'],
            "name": policy.get('name', ''),
            "loggingEnabled": policy.get('loggingEnabled', False),
            "origin": origin,
            "srcZone": zone_id_to_name.get(src_zone_id, ''),
            "dstZone": zone_id_to_name.get(dst_zone_id, ''),
        }
    }
