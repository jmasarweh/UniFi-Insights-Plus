"""
UniFi Log Insight - Technitium DNS Query Logs Poller (multi-server)

Polls one or more Technitium DNS Servers (Query Logs (Sqlite) app) for DNS
query logs, maps them to the standard log schema, enriches with GeoIP/threat
data, and inserts via the shared Database class.

Supports a cluster of Technitium instances: each configured server is polled
independently with its own rowNumber cursor and connection status. Technitium
returns the resolved answer inline in each record, so no separate DNS
resolution step is needed; API tokens are non-expiring, so there is no
session/SID handling.

Compatible with Technitium DNS Server 15.x. Verified against a live 15.3
server (2026-07-10): the /api/apps/list and /api/logs/query endpoints and the
query-log record schema are unchanged, and blocked queries that return the
sinkhole address inline (responseType=Blocked with an A answer) are already
discarded by _parse_answer.
"""

import ipaddress
import json
import logging
import os
import re
import threading
import time
import uuid
from datetime import datetime, timezone

import requests
import urllib3

from db import decrypt_api_key

logger = logging.getLogger(__name__)

# Technitium responseType values that represent a blocked/dropped query.
_BLOCK_RESPONSE_TYPES = {'BLOCKED', 'UPSTREAMBLOCKED', 'DROPPED'}

# rcodes that indicate a usable answer (others have nothing to resolve).
_OK_RCODES = {'NOERROR', ''}

# DNS record types that carry an IP answer.
_RESOLVABLE_TYPES = {'A', 'AAAA'}


def _is_private(ip_str):
    """Return True if the IP is private/reserved, or on any parse failure."""
    try:
        return ipaddress.ip_address(ip_str).is_private
    except (ValueError, TypeError):
        return True


def _env_verify_tls(default=True):
    """Resolve TLS verification from the TECHNITIUM_VERIFY_TLS env var."""
    v = os.environ.get('TECHNITIUM_VERIFY_TLS', '').lower()
    if v in ('true', '1', 'yes'):
        return True
    if v in ('false', '0', 'no'):
        return False
    return default


class TechnitiumPoller:
    """Multi-server Technitium DNS query-log poller.

    Each server in ``self.servers`` is a dict:
        {'id': str, 'name': str, 'host': str, 'token': str, 'verify_tls': bool}
    Per-server rowNumber cursors live in ``self._cursors`` (id -> int) and
    poll status in ``self._statuses`` (id -> {connected,last_poll,last_error}).
    """

    TIMEOUT = 10            # seconds per HTTP request
    ENTRIES_PER_PAGE = 100  # Technitium API maximum
    MAX_PAGES_PER_POLL = 50  # safety cap: at most 5000 new entries per server per poll

    def __init__(self, db, enricher=None):
        self._db = db
        self._enricher = enricher

        # Per-server connection state
        self._sessions = {}   # id -> requests.Session
        self._cursors = {}    # id -> rowNumber
        self._statuses = {}   # id -> {connected,last_poll,last_error}
        self._app_info = {}   # id -> (app_name, class_path) of the detected Query Logs app

        # Polling state
        self._poll_thread = None
        self._poll_stop = threading.Event()
        self._lock = threading.Lock()

        # Config (loaded from DB + env)
        self.enabled = False
        self.servers = []
        self.poll_interval = 60
        self.enrichment_enabled = 'both'

        try:
            self._resolve_config()
        except Exception as e:
            logger.warning("TechnitiumPoller: config resolution failed (DB may not be ready): %s", e)

    # ── Config Resolution ────────────────────────────────────────────────────

    def _resolve_config(self):
        """Load settings: env var > system_config DB > default."""
        servers = []

        # Servers configured via the UI (stored as a JSON list with encrypted tokens)
        raw_servers = self._db.get_config('technitium_servers', []) or []
        if isinstance(raw_servers, list):
            for s in raw_servers:
                if not isinstance(s, dict):
                    continue
                tok = s.get('token', '')
                servers.append({
                    'id': s.get('id') or uuid.uuid4().hex,
                    'name': (s.get('name') or s.get('host') or 'Technitium').strip(),
                    'host': (s.get('host') or '').rstrip('/'),
                    'token': decrypt_api_key(tok) if tok else '',
                    'verify_tls': bool(s.get('verify_tls', True)),
                    'env': False,
                })

        # Legacy single-server keys (pre-multi-server) → migrate into the list
        legacy_host = (self._db.get_config('technitium_host', '') or '').rstrip('/')
        if legacy_host and not any(srv['host'] == legacy_host for srv in servers):
            legacy_tok = self._db.get_config('technitium_token', '')
            servers.append({
                'id': 'legacy',
                'name': legacy_host,
                'host': legacy_host,
                'token': decrypt_api_key(legacy_tok) if legacy_tok else '',
                'verify_tls': bool(self._db.get_config('technitium_verify_tls', True)),
                'env': False,
            })

        # Single-server env override (convenience for simple deployments)
        env_host = os.environ.get('TECHNITIUM_HOST')
        env_token = os.environ.get('TECHNITIUM_TOKEN')
        if env_host and env_token:
            servers.append({
                'id': 'env',
                'name': 'env',
                'host': env_host.rstrip('/'),
                'token': env_token,
                'verify_tls': _env_verify_tls(),
                'env': True,
            })

        self.servers = servers

        # Global poll interval
        env_interval = os.environ.get('TECHNITIUM_POLL_INTERVAL', '')
        try:
            parsed_interval = int(env_interval) if env_interval else 0
        except ValueError:
            logger.warning("Invalid TECHNITIUM_POLL_INTERVAL '%s', ignoring", env_interval)
            parsed_interval = 0
        if parsed_interval and not (15 <= parsed_interval <= 86400):
            logger.warning("TECHNITIUM_POLL_INTERVAL %d out of range (15-86400), ignoring", parsed_interval)
            parsed_interval = 0
        if not parsed_interval:
            try:
                parsed_interval = int(self._db.get_config('technitium_poll_interval', 60))
            except (ValueError, TypeError):
                parsed_interval = 60
            if not (15 <= parsed_interval <= 86400):
                parsed_interval = 60
        self.poll_interval = parsed_interval

        value = self._db.get_config('technitium_enrichment', 'both')
        self.enrichment_enabled = value if value in ('none', 'geoip', 'threat', 'both') else 'both'

        # Per-server cursors
        cursors = self._db.get_config('technitium_cursors', {}) or {}
        self._cursors = {k: int(v) for k, v in cursors.items()} if isinstance(cursors, dict) else {}

        # Master toggle: env > DB > default
        enabled_env = os.environ.get('TECHNITIUM_ENABLED', '').lower()
        if enabled_env in ('true', '1', 'yes'):
            master = True
        elif enabled_env in ('false', '0', 'no'):
            master = False
        else:
            master = bool(self._db.get_config('technitium_enabled', False))

        has_usable = any(s['host'] and s['token'] for s in self.servers)
        self.enabled = master and has_usable

        # Auto-enable when env server is fully specified
        if (not master and env_host and env_token):
            try:
                self._db.set_config('technitium_enabled', True)
                self.enabled = True
                logger.info("Technitium auto-enabled (TECHNITIUM_HOST + TECHNITIUM_TOKEN env vars detected)")
            except Exception as e:
                logger.debug("Failed to auto-enable Technitium: %s", e)

    def set_enricher(self, enricher):
        self._enricher = enricher

    def reload_config(self):
        """Re-read settings from DB/env. Restart polling if changed."""
        old_enabled = self.enabled
        old_hosts = {s['id']: s['host'] for s in self.servers}

        for sess in self._sessions.values():
            try:
                sess.close()
            except Exception:
                logger.debug("Failed to close Technitium session on reload", exc_info=True)
        self._sessions = {}
        self._app_info = {}

        self._resolve_config()
        logger.info("Technitium config reloaded (enabled=%s, servers=%d)", self.enabled, len(self.servers))

        new_hosts = {s['id']: s['host'] for s in self.servers}
        was_polling = self._poll_thread is not None and self._poll_thread.is_alive()
        if was_polling or (self.enabled and (old_enabled != self.enabled or old_hosts != new_hosts)):
            self.start_polling()

    def get_config_source(self, key: str) -> str:
        from deps import get_config_source
        env_map = {'poll_interval': 'TECHNITIUM_POLL_INTERVAL', 'enabled': 'TECHNITIUM_ENABLED'}
        return get_config_source(self._db, key, env_map, 'technitium')

    def get_settings_info(self) -> dict:
        """Return current config with per-server status for the Settings UI."""
        return {
            'enabled': self.enabled,
            'poll_interval': self.poll_interval,
            'poll_interval_source': self.get_config_source('poll_interval'),
            'enrichment': self.enrichment_enabled,
            'servers': [
                {
                    'id': s['id'],
                    'name': s['name'],
                    'host': s['host'],
                    'token_set': bool(s['token']),
                    'verify_tls': s['verify_tls'],
                    'env_managed': s.get('env', False),
                    'backend': (self._app_info.get(s['id']) or (None, None))[0],
                    'status': self._get_status(s['id']),
                }
                for s in self.servers
            ],
        }

    # ── Per-server status ──────────────────────────────────────────────────────

    def _get_status(self, sid: str) -> dict:
        """In-memory status (receiver process) with DB fallback (API process)."""
        with self._lock:
            if sid in self._statuses:
                return dict(self._statuses[sid])
        db_status = self._db.get_config('technitium_poll_status', {}) or {}
        if isinstance(db_status, dict) and sid in db_status:
            return dict(db_status[sid])
        return {'connected': False, 'last_poll': None, 'last_error': None}

    def _set_status(self, sid: str, connected: bool, error: str = None):
        now = datetime.now(tz=timezone.utc).isoformat()
        with self._lock:
            self._statuses[sid] = {'connected': connected, 'last_poll': now, 'last_error': error}
            snapshot = dict(self._statuses)
        try:
            self._db.set_config('technitium_poll_status', snapshot)
        except Exception as e:
            logger.debug("Failed to persist Technitium poll status: %s", e)

    # ── HTTP ─────────────────────────────────────────────────────────────────

    def _get_session(self, server: dict) -> requests.Session:
        sid = server['id']
        sess = self._sessions.get(sid)
        if sess is None:
            sess = requests.Session()
            sess.verify = server.get('verify_tls', True)
            if not sess.verify:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            self._sessions[sid] = sess
        return sess

    def _api_get(self, server: dict, path: str, params: dict) -> dict:
        query = dict(params)
        query['token'] = server['token']
        url = f"{server['host']}{path}"
        session = self._get_session(server)
        try:
            resp = session.get(url, params=query, timeout=self.TIMEOUT)
        except requests.RequestException as e:
            raise ConnectionError(f"Technitium API request failed: {e}") from e

        resp.raise_for_status()
        data = resp.json()
        status = data.get('status')
        if status and status != 'ok':
            if status == 'invalid-token':
                raise PermissionError("Technitium authentication failed: invalid token")
            raise RuntimeError(f"Technitium API error: {data.get('errorMessage') or status}")
        return data

    @staticmethod
    def _find_query_logs_app(apps) -> tuple[str, str] | None:
        """Return (app_name, class_path) of the first app exposing query logs.

        Works for any Query Logs backend (Sqlite, MySQL, MariaDB, PostgreSQL):
        all of them flag their DNS app with isQueryLogs=true.
        """
        for app in apps or []:
            for dns_app in app.get('dnsApps', []):
                if dns_app.get('isQueryLogs'):
                    return app.get('name'), dns_app.get('classPath')
        return None

    def _discover_app(self, server: dict) -> tuple[str, str]:
        """Detect and cache the installed Query Logs app for a server."""
        sid = server['id']
        cached = self._app_info.get(sid)
        if cached:
            return cached
        data = self._api_get(server, '/api/apps/list', {})
        resp = data.get('response', data)
        info = self._find_query_logs_app(resp.get('apps', []))
        if not info or not info[1]:
            raise RuntimeError("No Query Logs app installed (need Query Logs for "
                               "Sqlite, MySQL, MariaDB, or PostgreSQL)")
        self._app_info[sid] = info
        logger.info("Technitium[%s] using Query Logs app: %s (%s)", server['name'], info[0], info[1])
        return info

    def _fetch_page(self, server: dict, page: int) -> dict:
        app_name, class_path = self._discover_app(server)
        return self._api_get(server, '/api/logs/query', {
            'classPath': class_path,
            'name': app_name,
            'pageNumber': page,
            'entriesPerPage': self.ENTRIES_PER_PAGE,
            'descending': 'true',
        })

    # ── Record Mapping ─────────────────────────────────────────────────────────

    @staticmethod
    def _parse_timestamp(raw) -> datetime:
        """Parse Technitium ISO-8601 timestamps (handles 'Z' and 7-digit
        fractional seconds that datetime.fromisoformat rejects)."""
        if not raw:
            return datetime.now(tz=timezone.utc)
        s = str(raw).strip()
        try:
            if s.endswith('Z'):
                s = s[:-1] + '+00:00'
            m = re.match(r'^(.*\.\d{6})\d*([+-]\d{2}:\d{2})$', s)
            if m:
                s = m.group(1) + m.group(2)
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except (ValueError, TypeError):
            return datetime.now(tz=timezone.utc)

    @staticmethod
    def _parse_answer(answer, action, qtype, rcode) -> tuple[str | None, str | None]:
        """Extract the first A/AAAA IP from a Technitium answer string.

        Returns (dns_answer_ip, public_dst_ip). public_dst_ip is None for
        private/blocked/failed answers (used for GeoIP/threat enrichment).
        """
        if action == 'block' or not answer or (rcode or '').upper() not in _OK_RCODES:
            return None, None
        if qtype not in _RESOLVABLE_TYPES:
            return None, None
        for part in str(answer).split(','):
            tokens = part.strip().split()
            if len(tokens) >= 2 and tokens[0].upper() in _RESOLVABLE_TYPES:
                ip = tokens[1].rstrip('.')
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    continue
                dst = ip if not _is_private(ip) else None
                return ip, dst
        return None, None

    def _map_query(self, record: dict, server_name: str) -> dict:
        """Map a Technitium query-log record to the standard log dict."""
        src_ip = record.get('clientIpAddress') or None
        domain = record.get('qname') or ''
        qtype = (record.get('qtype') or '').upper()
        response_type = (record.get('responseType') or '')
        rcode = record.get('rcode') or ''
        protocol = (record.get('protocol') or '').upper() or 'UDP'

        timestamp = self._parse_timestamp(record.get('timestamp'))
        action = 'block' if response_type.upper() in _BLOCK_RESPONSE_TYPES else 'allow'
        desc = response_type or rcode or None

        dns_answer, dst_ip = self._parse_answer(record.get('answer'), action, qtype, rcode)

        # Tag the raw log with the originating cluster node for traceability
        raw = {'server': server_name, **record}

        return {
            'timestamp': timestamp,
            'log_type': 'dns',
            'direction': None,
            'src_ip': src_ip,
            'src_port': None,
            'dst_ip': dst_ip,
            'dst_port': 53,
            'protocol': protocol,
            'service_name': None,
            'rule_name': None,
            'rule_desc': desc,
            'rule_action': action,
            'interface_in': None,
            'interface_out': None,
            'mac_address': None,
            'hostname': None,
            'dns_query': domain or None,
            'dns_type': qtype or None,
            'dns_answer': dns_answer,
            'dhcp_event': None,
            'wifi_event': None,
            'geo_country': None,
            'geo_city': None,
            'geo_lat': None,
            'geo_lon': None,
            'asn_number': None,
            'asn_name': None,
            'threat_score': None,
            'threat_categories': None,
            'rdns': None,
            'abuse_usage_type': None,
            'abuse_hostnames': None,
            'abuse_total_reports': None,
            'abuse_last_reported': None,
            'abuse_is_whitelisted': None,
            'abuse_is_tor': None,
            'src_device_name': None,
            'dst_device_name': None,
            'remote_ip': dst_ip,
            'source': 'technitium',
            'raw_log': json.dumps(raw),
        }

    # ── Polling ────────────────────────────────────────────────────────────────

    def _poll_server(self, server: dict):
        """Fetch + insert new query-log entries for a single server."""
        sid = server['id']
        name = server['name']
        cursor = self._cursors.get(sid, 0)
        first_run = (cursor == 0)
        try:
            data = self._fetch_page(server, 1)
            resp = data.get('response', data)
            entries = resp.get('entries', []) or []
            total_pages = int(resp.get('totalPages', 1) or 1)

            if not entries:
                self._set_status(sid, True)
                return

            newest_row = entries[0].get('rowNumber', 0)
            if not first_run and newest_row < cursor:
                logger.warning("Technitium[%s] rowNumber reset (newest=%d < cursor=%d); resetting",
                               name, newest_row, cursor)
                cursor = 0
                first_run = True

            new_entries = []
            max_row = cursor

            if first_run:
                for e in entries:
                    new_entries.append(e)
                    max_row = max(max_row, e.get('rowNumber', 0))
                logger.info("Technitium[%s] first poll: priming from %d recent queries", name, len(entries))
            else:
                page = 1
                pages_fetched = 0
                done = False
                cur_entries = entries
                while True:
                    for e in cur_entries:
                        row = e.get('rowNumber', 0)
                        if row <= cursor:
                            done = True
                            break
                        new_entries.append(e)
                        max_row = max(max_row, row)
                    pages_fetched += 1
                    if done or page >= total_pages or pages_fetched >= self.MAX_PAGES_PER_POLL:
                        break
                    page += 1
                    nxt = self._fetch_page(server, page)
                    cur_entries = nxt.get('response', nxt).get('entries', []) or []
                    if not cur_entries:
                        break
                if pages_fetched >= self.MAX_PAGES_PER_POLL and not done:
                    logger.warning("Technitium[%s] hit page cap (%d entries); some queries may be "
                                   "skipped — consider a shorter poll interval.",
                                   name, self.MAX_PAGES_PER_POLL * self.ENTRIES_PER_PAGE)

            if not new_entries:
                self._set_status(sid, True)
                return

            logs = []
            for record in reversed(new_entries):
                parsed = self._map_query(record, name)
                if self.enrichment_enabled != 'none' and self._enricher:
                    try:
                        parsed = self._enricher.enrich(parsed)
                    except Exception as e:
                        logger.debug("Technitium[%s] enrichment failed for %s: %s",
                                     name, parsed.get('dns_query', '?'), e)
                logs.append(parsed)

            self._db.insert_technitium_batch(logs, sid, max_row)
            self._cursors[sid] = max_row
            self._set_status(sid, True)
            logger.info("Technitium[%s] poll: inserted %d queries (cursor=%d)", name, len(logs), max_row)

        except Exception as e:
            logger.error("Technitium[%s] poll failed: %s", name, e)
            self._set_status(sid, False, str(e))

    def poll(self):
        """Poll every configured, usable server in turn."""
        for server in self.servers:
            if self._poll_stop.is_set():
                return
            if not (server['host'] and server['token']):
                continue
            self._poll_server(server)

    def start_polling(self):
        """Start (or restart) the background polling daemon thread."""
        self.stop_polling()

        if not self.enabled:
            try:
                self._db.set_config('technitium_poll_status', None)
            except Exception:
                logger.debug("Failed to clear stale Technitium poll status", exc_info=True)
            return

        self._poll_stop = threading.Event()
        poll_interval = self.poll_interval

        def _poll_loop():
            if self._enricher:
                for _ in range(10):
                    if self._poll_stop.is_set():
                        return
                    unifi = getattr(self._enricher, 'unifi', None)
                    if unifi and unifi.has_device_names():
                        break
                    time.sleep(1)
            self.poll()
            while not self._poll_stop.wait(poll_interval):
                self.poll()

        self._poll_thread = threading.Thread(target=_poll_loop, daemon=True, name='technitium-poller')
        self._poll_thread.start()
        logger.info("Technitium polling started (interval=%ds, servers=%d)",
                    poll_interval, sum(1 for s in self.servers if s['host'] and s['token']))

    def stop_polling(self):
        """Stop the background polling thread if running."""
        if self._poll_thread is not None and self._poll_thread.is_alive():
            self._poll_stop.set()
            self._poll_thread.join(timeout=5)
            logger.info("Technitium polling stopped")
        for sess in self._sessions.values():
            try:
                sess.close()
            except Exception:
                logger.debug("Failed to close Technitium session on stop", exc_info=True)
        self._sessions = {}

    # ── Test Connection ──────────────────────────────────────────────────────

    def test_connection(self, host: str, token: str, verify: bool = True) -> dict:
        """Test a single Technitium server: connectivity, token, and that a
        Query Logs app (any backend) is installed and queryable."""
        test_host = (host or '').rstrip('/')
        if not test_host or not token:
            return {'success': False, 'error': 'Host and API token are required'}

        session = requests.Session()
        session.verify = bool(verify)
        if not session.verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        def _check_status(payload):
            st = payload.get('status')
            if st == 'invalid-token':
                return 'Authentication failed: invalid API token'
            if st and st != 'ok':
                return f"Technitium error: {payload.get('errorMessage') or st}"
            return None

        try:
            # 1) Discover which Query Logs backend is installed (Sqlite/MySQL/MariaDB/PostgreSQL)
            apps_resp = session.get(f"{test_host}/api/apps/list",
                                    params={'token': token}, timeout=self.TIMEOUT)
            apps_resp.raise_for_status()
            apps_data = apps_resp.json()
            err = _check_status(apps_data)
            if err:
                return {'success': False, 'error': err}
            info = self._find_query_logs_app(apps_data.get('response', {}).get('apps', []))
            if not info or not info[1]:
                return {'success': False,
                        'error': 'No Query Logs app installed. Install one on the Technitium server '
                                 '(Apps > Store > Query Logs for Sqlite, MySQL, MariaDB, or PostgreSQL).'}
            app_name, class_path = info

            # 2) Verify we can actually query it
            resp = session.get(
                f"{test_host}/api/logs/query",
                params={'token': token, 'classPath': class_path, 'name': app_name,
                        'pageNumber': 1, 'entriesPerPage': 1, 'descending': 'true'},
                timeout=self.TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
            err = _check_status(data)
            if err:
                return {'success': False, 'error': err}
            total = data.get('response', {}).get('totalEntries', 0)
            return {'success': True, 'total_queries': total, 'backend': app_name}
        except requests.ConnectionError:
            return {'success': False, 'error': f'Cannot connect to {test_host}'}
        except requests.Timeout:
            return {'success': False, 'error': f'Connection to {test_host} timed out'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
        finally:
            session.close()

    def token_for(self, server_id: str) -> str:
        """Return the stored plaintext token for a server id (for test reuse)."""
        for s in self.servers:
            if s['id'] == server_id:
                return s['token']
        return ''
