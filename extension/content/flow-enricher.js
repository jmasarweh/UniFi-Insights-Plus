/**
 * Feature 2: Enrich public IPs on UniFi Insights Flow View with
 * threat score, rDNS, and ASN data from Log Insight cache.
 *
 * Activated by 'uli-ready' event from controller-detector.js.
 * Runs in content script isolated world (has chrome.runtime access).
 *
 * UniFi DOM (verified against UniFi Network 9.x):
 * - Flow table wrapper: div.FLOWS_TABLE_WRAPPER_CLASSNAME
 * - Table header cells: thead th (text: "Source", "Src. IP", "Destination", etc.)
 * - Data rows: tbody tr.FLOWS_TABLE_ROW_CLASSNAME
 * - External source IP: img.FLOWS_SOURCE_FLAG_IMAGE_CLASSNAME in cell, <p> has IP
 * - External dest IP: img.FLOWS_DESTINATION_FLAG_IMAGE_CLASSNAME in cell, <p> has IP or "hostname (IP)"
 * - Local device: img.FLOWS_SOURCE_CLIENT_IMAGE_CLASSNAME (skip these)
 * - Cell inner div: div.cellInner__R2HCkU1s (append badge here)
 * - Columns are user-configurable: discover positions from header text
 */

window.addEventListener('uli-ready', function () {
  const config = window.__uliConfig;
  if (!config || !config.enableFlowEnrichment) return;

  const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/;
  const IPV6_RE = /(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,6}:|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}/;

  const ABUSE_CATEGORIES = {
    1: 'DNS Compromise', 2: 'DNS Poisoning', 3: 'Fraud Orders', 4: 'DDoS Attack',
    5: 'FTP Brute-Force', 6: 'Ping of Death', 7: 'Phishing', 8: 'Fraud VoIP',
    9: 'Open Proxy', 10: 'Web Spam', 11: 'Email Spam', 12: 'Blog Spam',
    13: 'VPN IP', 14: 'Port Scan', 15: 'Hacking', 16: 'SQL Injection',
    17: 'Spoofing', 18: 'Brute-Force', 19: 'Bad Web Bot', 20: 'Exploited Host',
    21: 'Web App Attack', 22: 'SSH', 23: 'IoT Targeted',
  };

  const THREAT_COLORS = {
    none:     { bg: '#34d39922', text: '#34d399', border: '#34d39944' },
    low:      { bg: '#60a5fa22', text: '#60a5fa', border: '#60a5fa44' },
    medium:   { bg: '#fbbf2422', text: '#fbbf24', border: '#fbbf2444' },
    high:     { bg: '#fb923c22', text: '#fb923c', border: '#fb923c44' },
    critical: { bg: '#f8717122', text: '#f87171', border: '#f8717144' },
  };

  let debounceTimer = null;
  let processing = false;

  // The flow table may not exist yet (user might be on a different sub-page).
  // Watch for it to appear.
  startWatching();

  function startWatching() {
    const wrapper = document.querySelector('.FLOWS_TABLE_WRAPPER_CLASSNAME');
    if (wrapper) {
      observeTable(wrapper);
      enrichFlowTable();
      return;
    }

    // Table not present — watch for SPA navigation to flow view
    const bodyObs = new MutationObserver(() => {
      const w = document.querySelector('.FLOWS_TABLE_WRAPPER_CLASSNAME');
      if (w) {
        bodyObs.disconnect();
        observeTable(w);
        enrichFlowTable();
      }
    });
    bodyObs.observe(document.body, { childList: true, subtree: true });
  }

  function observeTable(wrapper) {
    // Watch for content changes (pagination, sorting, filtering)
    const observer = new MutationObserver(() => {
      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => enrichFlowTable(), 500);
    });
    observer.observe(wrapper, { childList: true, subtree: true });

    // Watch for table re-mount (SPA navigation away and back)
    const bodyObs = new MutationObserver(() => {
      const w = document.querySelector('.FLOWS_TABLE_WRAPPER_CLASSNAME');
      if (w && !w._uliObserving) {
        w._uliObserving = true;
        observer.observe(w, { childList: true, subtree: true });
        enrichFlowTable();
      }
    });
    bodyObs.observe(document.body, { childList: true, subtree: true });
    wrapper._uliObserving = true;
  }

  /**
   * Build column name -> index map from current table headers.
   */
  function getColumnMap(table) {
    const headers = table.querySelectorAll('thead th');
    const map = {};
    for (let i = 0; i < headers.length; i++) {
      map[headers[i].textContent.trim()] = i;
    }
    return map;
  }

  /**
   * Scan the flow table and enrich external IP rows with threat badges.
   */
  async function enrichFlowTable() {
    if (processing) return;
    processing = true;

    try {
      const table = document.querySelector('.FLOWS_TABLE_WRAPPER_CLASSNAME table');
      if (!table) return;

      const tbody = table.querySelector('tbody');
      if (!tbody) return;

      const cols = getColumnMap(table);
      const rows = tbody.querySelectorAll('tr');
      const ipElements = [];

      // Prefer "Source"/"Destination" over "Src. IP"/"Dst. IP" when both exist
      const srcCol = cols['Source'] ?? cols['Src. IP'] ?? -1;
      const dstCol = cols['Destination'] ?? cols['Dst. IP'] ?? -1;
      const usingSrcName = 'Source' in cols;
      const usingDstName = 'Destination' in cols;

      for (const row of rows) {
        const cells = row.querySelectorAll('td');

        // Source IP
        if (srcCol >= 0 && srcCol < cells.length) {
          const cell = cells[srcCol];
          if (usingSrcName) {
            // Only enrich rows with a flag image (external IP)
            if (cell.querySelector('.FLOWS_SOURCE_FLAG_IMAGE_CLASSNAME')) {
              const ip = extractIP(cell);
              if (ip && !isPrivateIP(ip)) ipElements.push({ cell, ip });
            }
          } else {
            const ip = extractIP(cell);
            if (ip && !isPrivateIP(ip)) ipElements.push({ cell, ip });
          }
        }

        // Destination IP
        if (dstCol >= 0 && dstCol < cells.length) {
          const cell = cells[dstCol];
          if (usingDstName) {
            if (cell.querySelector('.FLOWS_DESTINATION_FLAG_IMAGE_CLASSNAME')) {
              const ip = extractIP(cell);
              if (ip && !isPrivateIP(ip)) ipElements.push({ cell, ip });
            }
          } else {
            const ip = extractIP(cell);
            if (ip && !isPrivateIP(ip)) ipElements.push({ cell, ip });
          }
        }
      }

      if (ipElements.length === 0) return;

      // Batch lookup unique IPs via service worker
      const uniqueIPs = [...new Set(ipElements.map(e => e.ip))];
      let threatData;
      try {
        const resp = await chrome.runtime.sendMessage({
          type: 'BATCH_THREAT_LOOKUP',
          ips: uniqueIPs,
        });
        if (!resp || !resp.ok || !resp.data) return;
        threatData = resp.data;
      } catch (e) {
        // Extension context invalidated
        return;
      }

      for (const { cell, ip } of ipElements) {
        const threat = threatData[ip];
        if (!threat) continue;
        // Skip if no useful data (no score, no rDNS, no ASN)
        const hasScore = threat.threat_score !== null && threat.threat_score !== undefined;
        const hasData = hasScore || threat.rdns || threat.asn_name;
        if (hasData) injectBadge(cell, ip, threat);
      }
    } finally {
      processing = false;
    }
  }

  /**
   * Extract an IPv4 address from a flow table cell.
   * Cell text may be a raw IP, or "hostname (IP)".
   */
  function extractIP(cell) {
    const textEl = cell.querySelector('p');
    if (!textEl) return null;
    const text = textEl.textContent.trim();
    const v4 = text.match(IPV4_RE);
    if (v4) return v4[0];
    const v6 = text.match(IPV6_RE);
    return v6 ? v6[0] : null;
  }

  /**
   * Inject a threat badge inline to the right of the IP text in a flow table cell.
   */
  function injectBadge(cell, ip, threat) {
    // Find the inner content div
    const cellInner = cell.querySelector('[class*="cellInner"]') || cell.querySelector('div');
    if (!cellInner) return;
    if (cellInner.querySelector('[data-uli-badge]')) return; // already injected

    // Make the cell inner a flex row so badge sits to the right of IP text
    cellInner.style.display = 'flex';
    cellInner.style.alignItems = 'center';
    cellInner.style.gap = '6px';

    // Truncate IPv6 addresses in the text element
    const textEl = cell.querySelector('p');
    if (textEl && ip.includes(':')) {
      const truncated = truncateIPv6(ip);
      if (truncated !== ip) {
        textEl.title = textEl.textContent.trim();
        textEl.textContent = textEl.textContent.replace(ip, truncated);
      }
    }

    const badge = document.createElement('span');
    badge.setAttribute('data-uli-badge', ip);
    badge.style.flexShrink = '0';

    const shadow = badge.attachShadow({ mode: 'closed' });
    const level = getThreatLevel(threat.threat_score);
    const colors = THREAT_COLORS[level];

    const parts = [];
    const hasScore = threat.threat_score !== null && threat.threat_score !== undefined;

    if (hasScore) {
      // Threat score pill with category tooltip
      const score = threat.threat_score;
      const tooltipLines = ['Threat Score: ' + score];
      if (threat.threat_categories && threat.threat_categories.length) {
        const decoded = threat.threat_categories.map(c => {
          if (c === 'blacklist') return 'Blacklist';
          return ABUSE_CATEGORIES[parseInt(c)] || ('Category ' + c);
        });
        tooltipLines.push(decoded.join(', '));
      }
      parts.push(
        '<span class="pill" style="background:' + colors.bg +
        ';color:' + colors.text +
        ';border:1px solid ' + colors.border +
        '" title="' + escapeAttr(tooltipLines.join('\n')) + '">' + score + '</span>'
      );

      // Show "Blacklist" label inline when the IP is blacklisted
      if (threat.threat_categories && threat.threat_categories.includes('blacklist')) {
        parts.push('<span class="tag" style="color:' + colors.text + ';border-color:' + colors.border + '">Blacklist</span>');
      }
    } else {
      // No threat score — show a green filled circle
      parts.push(
        '<span class="dot" title="No threat score"></span>'
      );
    }

    // rDNS (shorter truncation for inline display)
    if (threat.rdns) {
      const rdns = threat.rdns.length > 16 ? threat.rdns.slice(0, 14) + '\u2026' : threat.rdns;
      parts.push('<span class="meta" title="' + escapeAttr(threat.rdns) + '">' + escapeHtml(rdns) + '</span>');
    }

    // ASN (shorter truncation for inline display)
    if (threat.asn_name) {
      const asn = threat.asn_name.length > 14 ? threat.asn_name.slice(0, 12) + '\u2026' : threat.asn_name;
      parts.push('<span class="meta asn" title="' + escapeAttr(threat.asn_name) + '">' + escapeHtml(asn) + '</span>');
    }

    shadow.innerHTML =
      '<style>' +
      ':host{display:inline-flex;align-items:center;gap:3px;' +
      'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;font-size:10px;line-height:1}' +
      '.pill{padding:1px 5px;border-radius:9999px;font-size:10px;font-weight:600;' +
      'cursor:pointer;white-space:nowrap;flex-shrink:0}' +
      '.pill:hover{filter:brightness(1.3)}' +
      '.dot{width:8px;height:8px;border-radius:50%;background:#34d399;flex-shrink:0}' +
      '.tag{padding:1px 4px;border-radius:4px;font-size:9px;font-weight:600;border:1px solid;white-space:nowrap;flex-shrink:0}' +
      '.meta{color:#9ca3af;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100px}' +
      '.asn{color:#6b7280}' +
      '</style>' +
      parts.join('');

    // Click pill/dot -> open Log Insight in the embedded tab, filtered to this IP
    const clickTarget = shadow.querySelector('.pill') || shadow.querySelector('.dot');
    if (clickTarget) {
      clickTarget.style.cursor = 'pointer';
      clickTarget.addEventListener('click', (e) => {
        e.stopPropagation();
        e.preventDefault();
        window.dispatchEvent(new CustomEvent('uli-navigate', { detail: { ip } }));
      });
    }

    cellInner.appendChild(badge);
  }

  // ── Helpers ─────────────────────────────────────────────────────────────

  function truncateIPv6(ip) {
    if (ip.length <= 20) return ip;
    return ip.slice(0, 17) + '\u2026';
  }

  function isPrivateIP(ip) {
    if (!ip) return true;
    // IPv6 private ranges
    if (ip.includes(':')) {
      const lower = ip.toLowerCase();
      if (lower === '::1' || lower.startsWith('fe80:') ||
          /^f[cd][0-9a-f]{2}:/.test(lower) ||
          lower === '::') return true;
      // IPv4-mapped IPv6 (::ffff:a.b.c.d) — check embedded IPv4
      const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
      if (mapped) return isPrivateIP(mapped[1]);
      return false;
    }
    // IPv4 private ranges
    if (ip.startsWith('10.') || ip.startsWith('192.168.') ||
        ip.startsWith('127.') || ip.startsWith('169.254.') ||
        ip.startsWith('100.64.')) return true;
    const m = ip.match(/^172\.(\d+)\./);
    if (m) {
      const oct = parseInt(m[1], 10);
      if (oct >= 16 && oct <= 31) return true;
    }
    if (ip === '0.0.0.0' || ip === '255.255.255.255') return true;
    return false;
  }

  function getThreatLevel(score) {
    if (score === 0 || score === null || score === undefined) return 'none';
    if (score < 25) return 'low';
    if (score < 50) return 'medium';
    if (score < 75) return 'high';
    return 'critical';
  }

  function escapeHtml(str) {
    const el = document.createElement('span');
    el.textContent = str;
    return el.innerHTML;
  }

  function escapeAttr(str) {
    return str.replace(/&/g, '&amp;').replace(/"/g, '&quot;')
              .replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
});
