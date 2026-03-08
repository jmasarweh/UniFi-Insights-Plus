"""Threat intel query endpoints (ip_threats cache + geo aggregation)."""

import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from psycopg2.extras import RealDictCursor

from deps import get_conn, put_conn
from query_helpers import parse_time_range

logger = logging.getLogger('api.threats')

router = APIRouter()


class BatchThreatRequest(BaseModel):
    ips: List[str]


@router.post("/api/threats/batch")
def batch_threat_lookup(req: BatchThreatRequest):
    """Batch lookup threat + rDNS + ASN data for multiple IPs from local cache.

    Queries ip_threats for AbuseIPDB data and logs for the latest rDNS/ASN
    per IP. No external API calls are made — purely a cache lookup.
    Max 50 IPs per request.
    """
    if len(req.ips) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 IPs per batch request")

    # Validate and deduplicate IPs (preserving order)
    seen = set()
    valid_ips = []
    for ip in req.ips:
        if ip in seen:
            continue
        try:
            ipaddress.ip_address(ip)
            valid_ips.append(ip)
            seen.add(ip)
        except ValueError:
            pass  # skip invalid IPs silently

    if not valid_ips:
        return {'results': {}}

    conn = get_conn()
    try:
        results = {}
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # 1. Threat data from ip_threats cache
            placeholders = ','.join(['%s::inet'] * len(valid_ips))
            cur.execute(
                f"""SELECT host(ip) as ip, threat_score, threat_categories,
                           abuse_usage_type, abuse_total_reports, abuse_is_tor
                    FROM ip_threats
                    WHERE ip IN ({placeholders})""",
                valid_ips
            )
            for row in cur.fetchall():
                item = dict(row)
                results[item['ip']] = item

            # 2. Latest rDNS + ASN from logs (DISTINCT ON picks most recent)
            # Time-bound to last 90 days to avoid full table scan
            rdns_cutoff = datetime.now(timezone.utc) - timedelta(days=90)
            cur.execute(
                f"""SELECT DISTINCT ON (combined_ip) combined_ip, rdns, asn_name
                    FROM (
                        SELECT host(src_ip) AS combined_ip, rdns, asn_name, timestamp
                        FROM logs
                        WHERE src_ip IN ({placeholders})
                          AND timestamp >= %s
                          AND (rdns IS NOT NULL OR asn_name IS NOT NULL)
                        UNION ALL
                        SELECT host(dst_ip) AS combined_ip, rdns, asn_name, timestamp
                        FROM logs
                        WHERE dst_ip IN ({placeholders})
                          AND timestamp >= %s
                          AND (rdns IS NOT NULL OR asn_name IS NOT NULL)
                    ) sub
                    ORDER BY combined_ip, timestamp DESC""",
                valid_ips + [rdns_cutoff] + valid_ips + [rdns_cutoff]
            )
            for row in cur.fetchall():
                ip = row['combined_ip']
                if ip in results:
                    results[ip]['rdns'] = row['rdns']
                    results[ip]['asn_name'] = row['asn_name']
                else:
                    # IP has log data but no threat cache entry
                    results[ip] = {
                        'ip': ip,
                        'threat_score': None,
                        'threat_categories': None,
                        'abuse_usage_type': None,
                        'abuse_total_reports': None,
                        'abuse_is_tor': None,
                        'rdns': row['rdns'],
                        'asn_name': row['asn_name'],
                    }

        # Fill in nulls for requested IPs not found in any table
        final = {}
        for ip in valid_ips:
            final[ip] = results.get(ip, None)

        return {'results': final}
    except Exception as e:
        conn.rollback()
        logger.exception("Error in batch threat lookup")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)


@router.get("/api/threats")
def list_threats(
    ip: Optional[str] = Query(None, description="Exact IP match"),
    min_score: int = Query(0, ge=0, le=100),
    max_score: Optional[int] = Query(None, ge=0, le=100),
    since: Optional[str] = Query(None, description="ISO datetime for looked_up_at lower bound"),
    limit: int = Query(100, ge=1, le=1000),
    sort: str = Query("threat_score", description="threat_score, looked_up_at, abuse_total_reports"),
    order: str = Query("desc", description="asc or desc"),
):
    allowed_sorts = {
        'threat_score': 'threat_score',
        'looked_up_at': 'looked_up_at',
        'abuse_total_reports': 'abuse_total_reports',
    }
    sort_col = allowed_sorts.get(sort, 'threat_score')
    sort_dir = 'ASC' if order.lower() == 'asc' else 'DESC'

    where = ["threat_score >= %s"]
    params = [min_score]

    if max_score is not None:
        where.append("threat_score <= %s")
        params.append(max_score)

    if ip:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid IP address: {ip}")
        where.append("ip = %s::inet")
        params.append(ip)

    if since:
        try:
            datetime.fromisoformat(since)
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail=f"Invalid datetime for since: {since}")
        where.append("looked_up_at >= %s::timestamptz")
        params.append(since)

    where_sql = " AND ".join(where) if where else "TRUE"

    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"SELECT COUNT(*) FROM ip_threats WHERE {where_sql}",
                params
            )
            total = cur.fetchone()['count']

            cur.execute(
                f"""SELECT host(ip) as ip, threat_score, threat_categories, looked_up_at,
                           abuse_usage_type, abuse_hostnames, abuse_total_reports,
                           abuse_last_reported, abuse_is_whitelisted, abuse_is_tor
                    FROM ip_threats
                    WHERE {where_sql}
                    ORDER BY {sort_col} {sort_dir}
                    LIMIT %s""",
                params + [limit]
            )
            rows = cur.fetchall()

        threats = []
        for row in rows:
            item = dict(row)
            if item.get('looked_up_at'):
                item['looked_up_at'] = item['looked_up_at'].isoformat()
            if item.get('abuse_last_reported'):
                item['abuse_last_reported'] = item['abuse_last_reported'].isoformat()
            threats.append(item)

        return {'threats': threats, 'total': total}
    except Exception as e:
        conn.rollback()
        logger.exception("Error querying ip_threats")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)


_GEO_SELECT = (
    "SELECT geo_lat as lat, geo_lon as lon, geo_country as country, "
    "geo_city as city, COUNT(*) as count, "
    "MAX(threat_score) as max_score, "
    "AVG(threat_score)::int as avg_score, "
    "COUNT(DISTINCT COALESCE(host(src_ip), host(dst_ip))) as unique_ips, "
    "(array_agg(id ORDER BY timestamp DESC))[1:50] as log_ids "
    "FROM logs "
)
_GEO_TAIL = (
    "AND geo_lat IS NOT NULL AND geo_lon IS NOT NULL "
    "GROUP BY geo_lat, geo_lon, geo_country, geo_city "
    "ORDER BY count DESC LIMIT 500"
)

_GEO_WHERE = {
    'threats': "WHERE timestamp >= %s AND threat_score > 70 ",
    'blocked_outbound': (
        "WHERE timestamp >= %s AND direction = 'outbound' "
        "AND rule_action = 'block' "
    ),
}


@router.get("/api/threats/geo")
def get_threats_geo(
    time_range: str = Query("24h", description="1h,6h,24h,7d,30d,60d"),
    mode: str = Query("threats", description="threats or blocked_outbound"),
):
    """Geo-aggregated threat data as GeoJSON for map visualization."""
    if mode not in _GEO_WHERE:
        raise HTTPException(status_code=400, detail="mode must be 'threats' or 'blocked_outbound'")

    cutoff = parse_time_range(time_range)
    if not cutoff:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                _GEO_SELECT + _GEO_WHERE[mode] + _GEO_TAIL,
                [cutoff]
            )

            rows = cur.fetchall()

        features = []
        total_events = 0
        for row in rows:
            total_events += row['count']
            features.append({
                'type': 'Feature',
                'geometry': {
                    'type': 'Point',
                    'coordinates': [float(row['lon']), float(row['lat'])],
                },
                'properties': {
                    'country': row['country'],
                    'city': row['city'],
                    'count': row['count'],
                    'max_score': row['max_score'] or 0,
                    'avg_score': row.get('avg_score', 0) or 0,
                    'unique_ips': row.get('unique_ips', 0) or 0,
                    'log_ids': row.get('log_ids') or [],
                },
            })

        return {
            'type': 'FeatureCollection',
            'features': features,
            'summary': {
                'total_points': len(features),
                'total_events': total_events,
                'time_range': time_range,
                'mode': mode,
            },
        }
    except Exception as e:
        conn.rollback()
        logger.exception("Error fetching threat geo data")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)
