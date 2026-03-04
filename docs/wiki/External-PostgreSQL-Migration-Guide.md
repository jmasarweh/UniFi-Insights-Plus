# External PostgreSQL Migration Guide

This guide explains how to migrate UniFi Log Insight from the embedded PostgreSQL database to an external PostgreSQL server, with focus on Docker connectivity pitfalls.

Use this with the in-app wizard: `Settings -> Database Migration`.

## What This Guide Solves

- Step 2 "Test Connection" timeouts
- Choosing the correct `DB_HOST` for your topology
- Docker Desktop vs Linux Docker host routing differences
- SSL mode setup (`disable`, `require`, `verify-ca`, `verify-full`)
- Safe post-migration rollout

## Quick Topology Matrix

Pick the `DB_HOST` value based on where PostgreSQL runs:

| Topology | `DB_HOST` | Notes |
|---|---|---|
| Same compose project | `postgres` (service name) | Only works when both services share the same compose network |
| Different compose projects on same host | Host-routable address | Use host IP or `host.docker.internal` (Desktop) |
| Docker Desktop (Windows/Mac) to host-mapped Postgres | `host.docker.internal` | Works by default |
| Linux Docker to host-mapped Postgres | Host gateway IP (for example `172.17.0.1`) or `host.docker.internal` with host-gateway mapping | `host.docker.internal` is not automatic on many Linux setups |
| Cloud PostgreSQL (RDS/Aurora/Cloud SQL/etc.) | Cloud hostname | Usually requires `DB_SSLMODE=require` or stricter |

Important:
- Do not use random container bridge IPs like `172.18.x.x` unless both containers are intentionally on that same routable network.
- Prefer host-mapped ports and host-routable addresses for separate compose projects.

## Prerequisites

- PostgreSQL 14+
- Dedicated database (recommended: `unifi_logs`)
- User with schema/table/index/function privileges
- Network/firewall allows container -> target DB on `DB_PORT` (default `5432`)

Minimum SQL setup:

```sql
CREATE USER unifi WITH PASSWORD 'your_password';
CREATE DATABASE unifi_logs OWNER unifi;

GRANT ALL ON SCHEMA public TO unifi;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO unifi;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO unifi;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO unifi;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO unifi;
```

## Connectivity Checks Before Wizard

## 1) Confirm Postgres is reachable on host

If Postgres container is mapped as `-p 5432:5432`, confirm on host:

```bash
psql -h 127.0.0.1 -p 5432 -U unifi -d unifi_logs -c "SELECT 1;"
```

## 2) Confirm reachability from UniFi Log Insight container path

Use the same host/port you plan to enter in the wizard:

```bash
docker exec -it unifi-log-insight sh -lc "nc -zv <DB_HOST> <DB_PORT>"
```

If this fails, Step 2 in the wizard will also fail.

## Linux-specific note

On Linux Docker, if you want to use `host.docker.internal`, add this to the `unifi-log-insight` service:

```yaml
extra_hosts:
  - "host.docker.internal:host-gateway"
```

Then use:
- `DB_HOST=host.docker.internal`
- `DB_PORT=<mapped-port>`

Without this mapping, `host.docker.internal` may not resolve.

## Migration Wizard Steps

## Step 1: Configure

In `Settings -> Database Migration`, set:
- Host
- Port
- Database Name (`unifi_logs`)
- Username
- Password
- SSL Mode

## Step 2: Test Connection

Expected success:
- "Connection successful"
- Server version shown
- Optional warning if unknown tables exist

If you get timeout/refused:
- Verify `DB_HOST` is host-routable from the app container
- Verify DB port mapping and firewall
- Do not use non-routable bridge IPs from unrelated Docker networks

If you get auth failed:
- Verify username/password for target DB user

If you get database does not exist:
- Create target DB first

## Step 3: Start Migration

The app:
- Validates target table safety
- Dumps embedded DB
- Restores to external DB
- Validates table counts

Do not restart during migration.

## Step 4: Generate Updated Compose

Paste your current `docker-compose.yml` into the wizard and generate patched output.

The patcher updates DB env vars and healthcheck for external DB mode.

After applying the compose output:
- Set `DB_PASSWORD` in `.env`
- Run:

```bash
docker compose up -d
```

## SSL Mode Guidance

| SSL Mode | Use When |
|---|---|
| `disable` | Local trusted network, no TLS required |
| `require` | TLS required, cert chain verification not enforced |
| `verify-ca` | TLS with CA verification |
| `verify-full` | TLS with CA verification + hostname validation |

If using `verify-ca` or `verify-full`:
- Ensure CA cert is mounted and `DB_SSLROOTCERT` points to it.
- Confirm the cert hostname matches `DB_HOST` when using `verify-full`.

## Common Failures and Fixes

| Error | Likely Cause | Fix |
|---|---|---|
| Could not connect / timeout | Wrong host routing | Use host-routable address and mapped port |
| Could not translate host name `host.docker.internal` | Linux host-gateway mapping missing | Add `extra_hosts` mapping or use gateway IP |
| Connection refused | DB not listening/mapped | Confirm `-p` mapping and Postgres bind/listen settings |
| Password authentication failed | Wrong credentials | Correct `DB_USER`/`DB_PASSWORD` |
| Target has unknown tables | Shared/wrong database | Use a dedicated DB for UniFi Log Insight |
| SSL required | Server enforces TLS | Set `DB_SSLMODE=require` or stricter |

## Post-Migration Checklist

1. Dashboard and Log Stream load normally.
2. New logs are being ingested.
3. `/api/health` is healthy.
4. Optional: remove old embedded `pgdata` volume only after verification.

## Rollback Plan

If external DB setup fails after migration attempt:
- Fix connectivity/credentials and rerun.
- Embedded `pgdata` remains your safety copy until you remove it.
- Do not delete `pgdata` until external operation is confirmed.

## Recommended Compose Patterns

## External DB in different compose project (host-mapped port)

```yaml
services:
  unifi-log-insight:
    image: ghcr.io/jmasarweh/unifi-log-insight:latest
    environment:
      DB_HOST: "host.docker.internal"
      DB_PORT: "5432"
      DB_NAME: "unifi_logs"
      DB_USER: "unifi"
      DB_PASSWORD: "${DB_PASSWORD}"
```

Linux alternative:
- Use gateway IP if not using host-gateway mapping.

## Same compose network

```yaml
services:
  postgres:
    image: postgres:16
  unifi-log-insight:
    environment:
      DB_HOST: "postgres"
      DB_PORT: "5432"
      DB_NAME: "unifi_logs"
      DB_USER: "unifi"
      DB_PASSWORD: "${DB_PASSWORD}"
```

## Support Notes

Before opening an issue, collect:
- Wizard test error message
- `docker logs unifi-log-insight`
- Your target topology (same compose, different compose, cloud DB)
- Sanitized DB env config (`DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_SSLMODE`)
