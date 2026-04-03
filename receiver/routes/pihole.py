"""Pi-hole v6 settings, connection test endpoints."""

import logging

from fastapi import APIRouter

from db import get_config, set_config, encrypt_api_key
from deps import enricher_db, signal_receiver, pihole_poller

logger = logging.getLogger('api.pihole')

router = APIRouter()


@router.get("/api/settings/pihole")
def get_pihole_settings():
    """Current Pi-hole settings (merged: env + DB + defaults)."""
    return pihole_poller.get_settings_info()


@router.put("/api/settings/pihole")
def update_pihole_settings(body: dict):
    """Save Pi-hole settings to system_config."""
    # Check if host changed so we can reset cursor
    current_host = get_config(enricher_db, 'pihole_host', '')

    if 'enabled' in body:
        set_config(enricher_db, 'pihole_enabled', body['enabled'])
        if not body['enabled']:
            set_config(enricher_db, 'pihole_poll_status', None)
    if 'host' in body:
        set_config(enricher_db, 'pihole_host', body['host'])
    if 'password' in body:
        val = body['password']
        # Only update password when a non-empty value is provided.
        # Empty string means "no change" (UI sends '' when user hasn't typed anything).
        if val:
            set_config(enricher_db, 'pihole_password', encrypt_api_key(val))
    if 'poll_interval' in body:
        set_config(enricher_db, 'pihole_poll_interval', body['poll_interval'])
    if 'enrichment' in body:
        set_config(enricher_db, 'pihole_enrichment', body['enrichment'])

    # Reset cursor when host changes so we re-fetch from the new instance
    new_host = body.get('host')
    if new_host is not None and new_host != current_host:
        set_config(enricher_db, 'pihole_last_cursor', 0)

    pihole_poller.reload_config()
    signal_receiver()

    return {"success": True}


@router.post("/api/settings/pihole/test")
def test_pihole_connection(body: dict):
    """Test Pi-hole connectivity and authentication."""
    host = body.get('host', '').strip()
    password = body.get('password', '')

    result = pihole_poller.test_connection(host, password)
    return result
