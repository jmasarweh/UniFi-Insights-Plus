"""Technitium DNS query-log settings and connection-test endpoints (multi-server)."""

import logging
import uuid

from fastapi import APIRouter, HTTPException

from db import get_config, set_config, encrypt_api_key
from deps import enricher_db, signal_receiver, technitium_poller

logger = logging.getLogger('api.technitium')

router = APIRouter()


@router.get("/api/settings/technitium")
def get_technitium_settings():
    """Current Technitium settings (merged: env + DB + defaults), with per-server status."""
    return technitium_poller.get_settings_info()


@router.put("/api/settings/technitium")
def update_technitium_settings(body: dict):
    """Save Technitium settings (global options + the list of cluster servers)."""
    # ── Validate global fields before persisting anything ──
    interval = None
    if 'poll_interval' in body:
        try:
            interval = int(body['poll_interval'])
        except (ValueError, TypeError):
            raise HTTPException(400, 'poll_interval must be an integer')
        if interval < 15 or interval > 86400:
            raise HTTPException(400, 'poll_interval must be between 15 and 86400 seconds')
    if 'enrichment' in body and body['enrichment'] not in ('none', 'geoip', 'threat', 'both'):
        raise HTTPException(400, 'enrichment must be one of: none, geoip, threat, both')

    # ── Servers list (token-preserving merge) ──
    servers_in = body.get('servers')
    if servers_in is not None:
        if not isinstance(servers_in, list):
            raise HTTPException(400, 'servers must be a list')

        existing = get_config(enricher_db, 'technitium_servers', []) or []
        existing_map = {e.get('id'): e for e in existing if isinstance(e, dict) and e.get('id')}
        old_host_by_id = {e.get('id'): (e.get('host') or '').rstrip('/')
                          for e in existing if isinstance(e, dict)}

        new_servers, seen = [], set()
        for s in servers_in:
            if not isinstance(s, dict):
                raise HTTPException(400, 'each server must be an object')
            if s.get('id') == 'env':
                continue  # env-managed servers are not persisted to the DB
            host = (s.get('host') or '').strip().rstrip('/')
            if not host:
                raise HTTPException(400, 'each server requires a host')
            sid = s.get('id') or uuid.uuid4().hex
            token = s.get('token')
            if token:
                enc_token = encrypt_api_key(token)
            else:  # blank on an existing server → keep the stored token
                enc_token = (existing_map.get(sid) or {}).get('token', '')
            new_servers.append({
                'id': sid,
                'name': (s.get('name') or host).strip(),
                'host': host,
                'token': enc_token,
                'verify_tls': bool(s.get('verify_tls', True)),
            })
            seen.add(sid)

        set_config(enricher_db, 'technitium_servers', new_servers)

        # Drop cursors for removed servers and reset cursor when a host changed
        new_host_by_id = {x['id']: x['host'] for x in new_servers}
        cursors = get_config(enricher_db, 'technitium_cursors', {}) or {}
        if isinstance(cursors, dict):
            set_config(enricher_db, 'technitium_cursors', {
                k: v for k, v in cursors.items()
                if k in seen and old_host_by_id.get(k) == new_host_by_id.get(k)
            })
        statuses = get_config(enricher_db, 'technitium_poll_status', {}) or {}
        if isinstance(statuses, dict):
            set_config(enricher_db, 'technitium_poll_status',
                       {k: v for k, v in statuses.items() if k in seen})

    # ── Global options ──
    if 'enabled' in body:
        set_config(enricher_db, 'technitium_enabled', bool(body['enabled']))
        if not body['enabled']:
            set_config(enricher_db, 'technitium_poll_status', None)
    if interval is not None:
        set_config(enricher_db, 'technitium_poll_interval', interval)
    if 'enrichment' in body:
        set_config(enricher_db, 'technitium_enrichment', body['enrichment'])

    technitium_poller.reload_config()
    signal_receiver()
    return {"success": True}


@router.post("/api/settings/technitium/test")
def test_technitium_connection(body: dict):
    """Test a single Technitium server's connectivity and authentication."""
    host = (body.get('host') or '').strip()
    token = body.get('token') or ''
    verify = body.get('verify_tls', True)

    # Editing an existing server with a blank token → reuse the stored token
    if not token and body.get('id'):
        token = technitium_poller.token_for(body['id'])

    return technitium_poller.test_connection(host, token, bool(verify))
