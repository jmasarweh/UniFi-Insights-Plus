/**
 * Shared utilities for ULI content scripts.
 *
 * Content scripts cannot use ES module imports, so this file exposes
 * utilities on window.__uliUtils (following the lib/url-utils.js IIFE
 * pattern). It MUST be listed first in the content scripts array so
 * that controller-detector.js, flow-enricher.js, tab-injector.js, and
 * panel-enricher.js can all consume from it.
 *
 * Canonical source for constants: lib/constants.js (keep in sync).
 */
(() => {
  let configPromise = null;

  // AbuseIPDB category code -> human-readable label
  const ABUSE_CATEGORIES = {
    1: 'DNS Compromise', 2: 'DNS Poisoning', 3: 'Fraud Orders', 4: 'DDoS Attack',
    5: 'FTP Brute-Force', 6: 'Ping of Death', 7: 'Phishing', 8: 'Fraud VoIP',
    9: 'Open Proxy', 10: 'Web Spam', 11: 'Email Spam', 12: 'Blog Spam',
    13: 'VPN IP', 14: 'Port Scan', 15: 'Hacking', 16: 'SQL Injection',
    17: 'Spoofing', 18: 'Brute-Force', 19: 'Bad Web Bot', 20: 'Exploited Host',
    21: 'Web App Attack', 22: 'SSH', 23: 'IoT Targeted',
  };

  const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/;

  function getThreatLevel(score) {
    if (score === null || score === undefined || !Number.isFinite(score) || score <= 0) return 'none';
    if (score < 25) return 'low';
    if (score < 50) return 'medium';
    if (score < 75) return 'high';
    return 'critical';
  }

  function isPrivateIP(ip) {
    if (!ip) return true;
    // IPv6 private ranges
    if (ip.includes(':')) {
      const lower = ip.toLowerCase();
      if (lower === '::1' || lower.startsWith('fe80:') ||
          /^f[cd][0-9a-f]{2}:/.test(lower) ||
          lower.startsWith('ff') ||
          lower.startsWith('2001:db8:') || lower === '2001:db8::' ||
          lower.startsWith('2001:2:0:') || lower === '2001:2::' ||
          lower === '::') return true;
      // IPv4-mapped IPv6 (::ffff:a.b.c.d) — check embedded IPv4
      const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
      if (mapped) return isPrivateIP(mapped[1]);
      return false;
    }
    // IPv4 private ranges
    if (ip.startsWith('0.') || ip.startsWith('10.') || ip.startsWith('192.168.') ||
        ip.startsWith('127.') || ip.startsWith('169.254.') ||
        ip.startsWith('192.0.2.') || ip.startsWith('198.51.100.') ||
        ip.startsWith('203.0.113.')) return true;
    // CGNAT 100.64.0.0/10 (100.64.* – 100.127.*)
    const cgnat = ip.match(/^100\.(\d+)\./);
    if (cgnat) {
      const oct = parseInt(cgnat[1], 10);
      if (oct >= 64 && oct <= 127) return true;
    }
    const m = ip.match(/^172\.(\d+)\./);
    if (m) {
      const oct = parseInt(m[1], 10);
      if (oct >= 16 && oct <= 31) return true;
    }
    const firstOct = parseInt(ip.split('.')[0], 10);
    if (!Number.isNaN(firstOct) && firstOct >= 224) return true;
    if (ip === '255.255.255.255') return true;
    return false;
  }

  /** Detect UniFi theme from header background color. */
  function detectTheme() {
    const header = document.querySelector('header[class*="unifi-portal"]');
    if (!header) return 'dark';
    const bg = getComputedStyle(header).backgroundColor;
    const m = bg.match(/(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/);
    if (!m) return 'dark';
    return (0.299 * +m[1] + 0.587 * +m[2] + 0.114 * +m[3]) < 128 ? 'dark' : 'light';
  }

  function escapeHtml(str) {
    const el = document.createElement('span');
    el.textContent = str;
    return el.innerHTML;
  }

  function escapeAttr(str) {
    return str.replace(/&/g, '&amp;').replace(/"/g, '&quot;')
              .replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  /** Pick smallest preset time range covering a timestamp's age. */
  function timeRangeForTimestamp(tsStr) {
    if (!tsStr || typeof tsStr !== 'string') return null;
    const d = new Date(tsStr.replace(/\bat\b/g, ''));
    if (Number.isNaN(d.getTime())) return null;
    const ageH = (Date.now() - d.getTime()) / 3600000;
    if (ageH < 0) return '1h';
    const thresholds = [[1,'1h'],[6,'6h'],[24,'24h'],[168,'7d'],[720,'30d'],[1440,'60d'],[2160,'90d'],[4320,'180d']];
    for (const [maxH, range] of thresholds) {
      if (ageH <= maxH) return range;
    }
    return '365d';
  }

  /**
   * Navigate to Log Insight filtered by IP.
   * If tab injection is enabled, dispatch uli-navigate to open in the
   * embedded tab. Otherwise, open a new browser tab.
   */
  function navigateToIP(ip, timestamp, dir) {
    const config = window.__uliConfig;
    const range = timeRangeForTimestamp(timestamp);
    const rangeParam = range ? '&range=' + range : '';
    const dirParam = (dir === 'src' || dir === 'dst') ? '&dir=' + dir : '';
    if (config && config.enableTabInjection && config.baseUrl) {
      window.dispatchEvent(new CustomEvent('uli-navigate', { detail: { ip, range, dir } }));
    } else if (config && config.baseUrl) {
      const theme = detectTheme();
      const sep = config.baseUrl.includes('?') ? '&' : '?';
      window.open(config.baseUrl + sep + 'theme=' + theme + '#logs?ip=' + encodeURIComponent(ip) + rangeParam + dirParam, '_blank');
    }
  }

  /**
   * Load extension config into the shared content-script window cache.
   * Multiple callers share the same in-flight request.
   */
  async function ensureConfig() {
    if (window.__uliConfig) return window.__uliConfig;
    if (configPromise) return configPromise;

    configPromise = (async () => {
      let config;
      try {
        const resp = await chrome.runtime.sendMessage({ type: 'GET_CONFIG' });
        if (!resp || !resp.ok) {
          console.debug('[ULI] GET_CONFIG returned non-ok:', resp);
          return null;
        }
        config = resp.data;
      } catch (e) {
        console.debug('[ULI] GET_CONFIG failed:', e);
        return null;
      }

      let baseUrl = '';
      try {
        const resp = await chrome.runtime.sendMessage({ type: 'GET_BASE_URL' });
        if (resp && resp.ok) baseUrl = resp.url || '';
      } catch (e) {
        console.debug('[ULI] GET_BASE_URL failed:', e);
      }

      window.__uliConfig = { ...config, baseUrl };
      return window.__uliConfig;
    })();

    const resolved = await configPromise;
    if (!resolved) {
      configPromise = null;
    }
    return resolved;
  }

  /**
   * Observe UniFi theme changes. UniFi re-renders the React tree on toggle,
   * replacing the header element. Debounced MutationObserver on document.body
   * detects the new header and fires the callback when the theme flips.
   *
   * Returns the MutationObserver (call .disconnect() on teardown).
   */
  function onThemeChange(callback) {
    let debounce = null;
    let known = detectTheme();
    const check = () => {
      const current = detectTheme();
      if (current !== known) {
        known = current;
        callback(current);
      }
    };
    const observer = new MutationObserver(() => {
      if (debounce) clearTimeout(debounce);
      debounce = setTimeout(check, 200);
    });
    observer.observe(document.body, { childList: true, subtree: true });
    return observer;
  }

  window.__uliUtils = Object.freeze({
    ABUSE_CATEGORIES,
    IPV4_RE,
    getThreatLevel,
    isPrivateIP,
    detectTheme,
    escapeHtml,
    escapeAttr,
    navigateToIP,
    onThemeChange,
    ensureConfig,
  });
})();
