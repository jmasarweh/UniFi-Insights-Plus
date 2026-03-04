"""Database migration endpoints — UI wizard for embedded → external PostgreSQL."""

import ipaddress
import logging
import os
import subprocess
import threading

import psycopg2
import yaml
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from db import is_external_db

logger = logging.getLogger('api.migration')

router = APIRouter()

# ── Constants ────────────────────────────────────────────────────────────────

APP_TABLES = frozenset({
    'logs', 'ip_threats', 'system_config', 'unifi_clients',
    'unifi_devices', 'mcp_tokens', 'mcp_audit', 'saved_views',
})
SYSTEM_DBS = frozenset({'postgres', 'template0', 'template1'})
LOCAL_HOSTS = frozenset({'127.0.0.1', 'localhost', 'localhost.localdomain', '::1'})
PGDATA = '/var/lib/postgresql/data'

# ── Migration state (single worker — safe in-memory) ────────────────────────

_migration_lock = threading.Lock()
_migration_state = {
    'status': 'idle',       # idle | running | complete | failed
    'step': '',
    'message': '',
    'progress_pct': 0,
    'details': {},
}


def _update_state(**kwargs):
    with _migration_lock:
        _migration_state.update(kwargs)


# ── Request model ────────────────────────────────────────────────────────────

class MigrationParams(BaseModel):
    host: str
    port: int = 5432
    dbname: str = 'unifi_logs'
    user: str = 'unifi'
    password: str = ''
    sslmode: str = 'disable'


class PatchComposeRequest(BaseModel):
    compose_yaml: str
    host: str
    port: int = 5432
    dbname: str = 'unifi_logs'
    user: str = 'unifi'
    sslmode: str = 'disable'


# ── Validation helpers ───────────────────────────────────────────────────────

def _validate_target(params: MigrationParams):
    if not params.host.strip():
        raise HTTPException(400, "Host is required")
    if not params.dbname.strip():
        raise HTTPException(400, "Database name is required")
    if not params.user.strip():
        raise HTTPException(400, "Username is required")
    if params.dbname.strip().lower() in SYSTEM_DBS:
        raise HTTPException(400, f"'{params.dbname}' is a system database — use a dedicated database")
    if params.host.strip().lower() in LOCAL_HOSTS:
        raise HTTPException(400, "Target cannot be localhost — that's the embedded database")


def _connect_params(params: MigrationParams) -> dict:
    cp = {
        'host': params.host.strip(),
        'port': params.port,
        'dbname': params.dbname.strip(),
        'user': params.user.strip(),
        'password': params.password,
        'connect_timeout': 10,
    }
    if params.sslmode and params.sslmode != 'disable':
        cp['sslmode'] = params.sslmode
    return cp


def _host_connectivity_hint(host: str, port: int) -> str:
    """Hint for common Docker-on-same-host routing mistakes."""
    host = host.strip()
    host_lc = host.lower()
    if host_lc == 'host.docker.internal':
        return (
            f'Tip: host.docker.internal works on Docker Desktop by default. On Linux, add '
            f'"extra_hosts: [\"host.docker.internal:host-gateway\"]" to this container or use the '
            f'host gateway IP, then connect to mapped port {port}.'
        )
    try:
        addr = ipaddress.ip_address(host)
        if addr in ipaddress.ip_network('172.16.0.0/12'):
            return (
                f'Tip: {host} looks like a Docker bridge/internal IP. From another container, '
                f'use a host-routable address (for example host.docker.internal on Docker Desktop '
                f'or the host gateway IP on Linux) and the mapped PostgreSQL port (for example {port}).'
            )
    except ValueError:
        if '.' not in host and host_lc not in {'host.docker.internal', 'localhost'}:
            return (
                f'Tip: {host} looks like a Docker service/container name. It only resolves inside the same '
                f'Docker network. If your DB container is on another network, use a host-routable address '
                f'(host.docker.internal on Docker Desktop or the host gateway IP on Linux) and mapped port {port}.'
            )
    return ''


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/api/migration/test-connection")
def test_connection(params: MigrationParams):
    _validate_target(params)
    cp = _connect_params(params)
    try:
        conn = psycopg2.connect(**cp)
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("SELECT version()")
            server_version = cur.fetchone()[0]
            cur.execute("""
                SELECT table_name FROM information_schema.tables
                WHERE table_schema = 'public'
            """)
            existing = {row[0] for row in cur.fetchall()}
        conn.close()

        foreign = existing - APP_TABLES
        return {
            'success': True,
            'message': 'Connection successful',
            'server_version': server_version,
            'existing_tables': sorted(existing),
            'foreign_tables': sorted(foreign),
            'has_foreign_tables': len(foreign) > 0,
        }
    except psycopg2.OperationalError as e:
        msg = str(e).strip()
        connectivity_hint = ''
        if 'password authentication failed' in msg:
            msg = 'Authentication failed — check username and password'
        elif (
            'could not connect to server' in msg
            or 'Connection refused' in msg
            or 'timeout expired' in msg
            or 'could not translate host name' in msg
        ):
            msg = f'Could not connect to {params.host}:{params.port} — check host, port, and firewall'
            connectivity_hint = _host_connectivity_hint(params.host, params.port)
        elif 'does not exist' in msg:
            msg = f'Database "{params.dbname}" does not exist on the server'
        return {'success': False, 'message': msg, 'connectivity_hint': connectivity_hint}


@router.post("/api/migration/start")
def start_migration(params: MigrationParams):
    _validate_target(params)
    with _migration_lock:
        if _migration_state['status'] == 'running':
            raise HTTPException(409, "Migration already in progress")
    if is_external_db():
        raise HTTPException(400, "Already using an external database — migration not available")

    _update_state(
        status='running', step='Starting...', message='',
        progress_pct=0, details={},
    )
    t = threading.Thread(target=_run_migration, args=(params,), daemon=True)
    t.start()
    return {'success': True, 'message': 'Migration started'}


@router.get("/api/migration/status")
def migration_status():
    with _migration_lock:
        state = dict(_migration_state)
    state['is_external'] = is_external_db()
    return state


@router.post("/api/migration/patch-compose")
def patch_compose(req: PatchComposeRequest):
    """Parse user's docker-compose.yml and patch DB-related keys."""
    # Parse YAML
    try:
        data = yaml.safe_load(req.compose_yaml)
    except yaml.YAMLError as e:
        return {'success': False, 'message': f'Invalid YAML: {e}'}

    if not isinstance(data, dict) or 'services' not in data:
        return {'success': False, 'message': 'Not a valid docker-compose file — missing "services" key.'}

    services = data['services']
    if not isinstance(services, dict):
        return {'success': False, 'message': 'Invalid "services" section in compose file.'}

    # Find target service — strict matching
    svc_name = None
    svc = None
    if 'unifi-log-insight' in services:
        svc_name = 'unifi-log-insight'
        svc = services[svc_name]
    else:
        for name, cfg in services.items():
            if isinstance(cfg, dict) and cfg.get('container_name') == 'unifi-log-insight':
                svc_name = name
                svc = cfg
                break

    if svc is None:
        return {
            'success': False,
            'message': "Could not find 'unifi-log-insight' service. Ensure your compose file "
                       "contains a service named 'unifi-log-insight' or with "
                       "container_name: unifi-log-insight."
        }

    # Build DB env vars to set
    db_vars = {
        'DB_HOST': req.host,
        'DB_PORT': str(req.port),
        'DB_NAME': req.dbname,
        'DB_USER': req.user,
        'DB_PASSWORD': '${DB_PASSWORD}',
    }

    # SSL-related vars
    ssl_keys_to_remove = set()
    if req.sslmode != 'disable':
        db_vars['DB_SSLMODE'] = req.sslmode
    else:
        ssl_keys_to_remove.update(['DB_SSLMODE', 'DB_SSLROOTCERT', 'DB_SSLCERT', 'DB_SSLKEY'])

    if req.sslmode == 'require':
        ssl_keys_to_remove.update(['DB_SSLROOTCERT', 'DB_SSLCERT', 'DB_SSLKEY'])

    if req.sslmode in ('verify-ca', 'verify-full'):
        db_vars['DB_SSLROOTCERT'] = '/certs/ca-certificate.crt'

    # Track which SSL keys the user already had (to preserve mTLS paths)
    existing_ssl_keys = set()
    env = svc.get('environment')
    if isinstance(env, dict):
        existing_ssl_keys = {k for k in env if k in ('DB_SSLCERT', 'DB_SSLKEY')}
    elif isinstance(env, list):
        for item in env:
            key = str(item).split('=', 1)[0] if '=' in str(item) else str(item)
            if key in ('DB_SSLCERT', 'DB_SSLKEY'):
                existing_ssl_keys.add(key)

    # For verify-ca/verify-full: only remove mTLS keys if user didn't have them
    if req.sslmode in ('verify-ca', 'verify-full'):
        for k in ('DB_SSLCERT', 'DB_SSLKEY'):
            if k not in existing_ssl_keys:
                ssl_keys_to_remove.add(k)

    # Patch environment
    if isinstance(env, dict):
        # Map format — merge
        env.update(db_vars)
        for k in ssl_keys_to_remove:
            env.pop(k, None)
    elif isinstance(env, list):
        # List format — update in-place, append new
        db_keys_set = set(db_vars.keys()) | ssl_keys_to_remove
        new_env = []
        seen = set()
        for item in env:
            key = str(item).split('=', 1)[0] if '=' in str(item) else str(item)
            if key in db_keys_set:
                if key in db_vars and key not in seen:
                    new_env.append(f'{key}={db_vars[key]}')
                    seen.add(key)
                # else: skip (removal or duplicate)
            else:
                new_env.append(item)
        # Append any DB vars not yet in the list
        for k, v in db_vars.items():
            if k not in seen:
                new_env.append(f'{k}={v}')
        svc['environment'] = new_env
    else:
        # No environment key or unexpected type — create as map
        svc['environment'] = dict(db_vars)

    # Add cert volume mount for verify-ca/verify-full
    if req.sslmode in ('verify-ca', 'verify-full'):
        volumes = svc.get('volumes', [])
        if not isinstance(volumes, list):
            volumes = []
        cert_mount = './certs:/certs:ro'
        if not any(cert_mount in str(v) for v in volumes):
            volumes.append(cert_mount)
        svc['volumes'] = volumes

    # Swap healthcheck to HTTP variant
    svc['healthcheck'] = {
        'test': ['CMD', 'python3', '-c',
                 "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')"],
        'interval': '15s',
        'timeout': '10s',
        'retries': 5,
        'start_period': '45s',
    }

    # Dump patched YAML
    patched = yaml.dump(data, default_flow_style=False, sort_keys=False)
    return {'success': True, 'compose_yaml': patched}


# ── Background migration runner ─────────────────────────────────────────────

def _run_migration(params: MigrationParams):
    try:
        _do_migration(params)
    except Exception as exc:
        logger.exception("Migration failed with unexpected error")
        _update_state(status='failed', step='Error', message=str(exc))


def _do_migration(params: MigrationParams):
    cp = _connect_params(params)

    # ── 5% Preflight: verify target is safe ──────────────────────────────
    _update_state(progress_pct=5, step='Preflight', message='Checking target database...')
    try:
        conn = psycopg2.connect(**cp)
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("""
                SELECT table_name FROM information_schema.tables
                WHERE table_schema = 'public'
            """)
            existing = {row[0] for row in cur.fetchall()}
        conn.close()
    except Exception as e:
        _update_state(status='failed', step='Preflight failed',
                      message=f'Cannot connect to target: {e}')
        return

    foreign = existing - APP_TABLES
    if foreign:
        _update_state(status='failed', step='Preflight failed',
                      message=f'Target has unknown tables: {", ".join(sorted(foreign))}. '
                              f'This may not be a dedicated UniFi Log Insight database.')
        return

    # ── 15% Count source rows ────────────────────────────────────────────
    _update_state(progress_pct=15, step='Counting source data',
                  message='Counting rows in embedded database...')
    source_counts = {}
    try:
        from deps import get_conn, put_conn
        sconn = get_conn()
        try:
            with sconn.cursor() as cur:
                for table in sorted(APP_TABLES):
                    try:
                        cur.execute(f"SELECT count(*) FROM {table}")  # noqa: S608 — table names from constant
                        source_counts[table] = cur.fetchone()[0]
                    except Exception:
                        source_counts[table] = -1
                        sconn.rollback()
        finally:
            put_conn(sconn)
    except Exception as e:
        _update_state(status='failed', step='Source count failed',
                      message=f'Cannot read embedded database: {e}')
        return

    _update_state(progress_pct=20, step='Counting source data',
                  message=f'Source: {source_counts.get("logs", 0)} log entries')

    # ── 25% pg_dump ──────────────────────────────────────────────────────
    _update_state(progress_pct=25, step='Dumping data',
                  message='Creating database dump...')
    dump_path = '/tmp/migration.dump'
    embedded_password = os.environ.get('DB_PASSWORD') or os.environ.get('POSTGRES_PASSWORD', 'changeme')
    dump_env = os.environ.copy()
    dump_env['PGPASSWORD'] = embedded_password

    try:
        result = subprocess.run(
            ['pg_dump', '-h', '127.0.0.1', '-U', 'unifi', '-d', 'unifi_logs',
             '-Fc', '--no-owner', '--no-privileges', '-f', dump_path],
            env=dump_env, capture_output=True, text=True, timeout=600,
        )
        if result.returncode != 0:
            _update_state(status='failed', step='Dump failed',
                          message=f'pg_dump error: {result.stderr.strip()[:500]}')
            return
    except subprocess.TimeoutExpired:
        _update_state(status='failed', step='Dump failed',
                      message='pg_dump timed out after 10 minutes')
        return
    except FileNotFoundError:
        _update_state(status='failed', step='Dump failed',
                      message='pg_dump not found — is PostgreSQL installed in the container?')
        return

    _update_state(progress_pct=50, step='Dumping data', message='Dump complete')

    # ── 55% pg_restore ───────────────────────────────────────────────────
    _update_state(progress_pct=55, step='Restoring data',
                  message='Restoring to external database...')
    restore_env = os.environ.copy()
    restore_env['PGPASSWORD'] = params.password
    if params.sslmode and params.sslmode != 'disable':
        restore_env['PGSSLMODE'] = params.sslmode

    try:
        result = subprocess.run(
            ['pg_restore', '-h', params.host.strip(), '-p', str(params.port),
             '-U', params.user.strip(), '-d', params.dbname.strip(),
             '--no-owner', '--no-privileges', '--clean', '--if-exists',
             dump_path],
            env=restore_env, capture_output=True, text=True, timeout=1800,
        )
        # Exit code 0 = success, 1 = non-fatal warnings, 2+ = fatal
        if result.returncode >= 2:
            _update_state(status='failed', step='Restore failed',
                          message=f'pg_restore error (exit {result.returncode}): '
                                  f'{result.stderr.strip()[:500]}')
            _cleanup_dump(dump_path)
            return
    except subprocess.TimeoutExpired:
        _update_state(status='failed', step='Restore failed',
                      message='pg_restore timed out after 30 minutes')
        _cleanup_dump(dump_path)
        return

    _update_state(progress_pct=80, step='Restoring data', message='Restore complete')

    # ── 85% Validate ─────────────────────────────────────────────────────
    _update_state(progress_pct=85, step='Validating',
                  message='Verifying row counts...')
    target_counts = {}
    try:
        conn = psycopg2.connect(**cp)
        conn.autocommit = True
        with conn.cursor() as cur:
            for table in sorted(APP_TABLES):
                try:
                    cur.execute(f"SELECT count(*) FROM {table}")  # noqa: S608
                    target_counts[table] = cur.fetchone()[0]
                except Exception:
                    target_counts[table] = -1
                    conn.rollback()
        conn.close()
    except Exception as e:
        _update_state(status='failed', step='Validation failed',
                      message=f'Cannot connect to target for validation: {e}')
        _cleanup_dump(dump_path)
        return

    # Build validation details
    validation = {}
    all_ok = True
    for table in sorted(APP_TABLES):
        src = source_counts.get(table, -1)
        tgt = target_counts.get(table, -1)
        if src <= 0:
            status = 'ok'  # empty or missing source — trivially fine
        elif tgt < src:
            status = 'mismatch'
            all_ok = False
        else:
            status = 'ok'
        validation[table] = {'source': src, 'target': tgt, 'status': status}

    if not all_ok:
        _update_state(
            status='failed', step='Validation failed',
            message='Target has fewer rows than source — partial restore detected',
            details={'validation': validation},
        )
        _cleanup_dump(dump_path)
        return

    # ── 95% Cleanup ──────────────────────────────────────────────────────
    _update_state(progress_pct=95, step='Cleaning up', message='Removing dump file...')
    _cleanup_dump(dump_path)

    # ── 100% Done ────────────────────────────────────────────────────────
    _update_state(
        status='complete', progress_pct=100, step='Complete',
        message=f'Migration complete — {target_counts.get("logs", 0)} log entries transferred',
        details={'validation': validation, 'target': {
            'host': params.host.strip(), 'port': params.port,
            'dbname': params.dbname.strip(), 'user': params.user.strip(),
            'sslmode': params.sslmode,
        }},
    )
    logger.info("Migration complete: %s log entries to %s:%s/%s",
                target_counts.get('logs', 0), params.host, params.port, params.dbname)


def _cleanup_dump(path: str):
    try:
        os.remove(path)
    except OSError:
        pass
