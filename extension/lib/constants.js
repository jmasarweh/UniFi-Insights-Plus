// Threat score color thresholds (matches ThreatSidebar.jsx)
export const THREAT_COLORS = {
  none:     { bg: '#34d39922', text: '#34d399', border: '#34d39944', label: 'Clean' },
  low:      { bg: '#60a5fa22', text: '#60a5fa', border: '#60a5fa44', label: 'Low' },
  medium:   { bg: '#fbbf2422', text: '#fbbf24', border: '#fbbf2444', label: 'Medium' },
  high:     { bg: '#fb923c22', text: '#fb923c', border: '#fb923c44', label: 'High' },
  critical: { bg: '#f8717122', text: '#f87171', border: '#f8717144', label: 'Critical' },
};

export function getThreatLevel(score) {
  if (score === null || score === undefined || score <= 0) return 'none';
  if (score < 25) return 'low';
  if (score < 50) return 'medium';
  if (score < 75) return 'high';
  return 'critical';
}

// AbuseIPDB category code -> human-readable label
export const ABUSE_CATEGORIES = {
  1: 'DNS Compromise', 2: 'DNS Poisoning', 3: 'Fraud Orders', 4: 'DDoS Attack',
  5: 'FTP Brute-Force', 6: 'Ping of Death', 7: 'Phishing', 8: 'Fraud VoIP',
  9: 'Open Proxy', 10: 'Web Spam', 11: 'Email Spam', 12: 'Blog Spam',
  13: 'VPN IP', 14: 'Port Scan', 15: 'Hacking', 16: 'SQL Injection',
  17: 'Spoofing', 18: 'Brute-Force', 19: 'Bad Web Bot', 20: 'Exploited Host',
  21: 'Web App Attack', 22: 'SSH', 23: 'IoT Targeted',
};

// Default Log Insight URL to try on startup
export const DEFAULT_BASE_URL = 'http://localhost:8090';

// Cache TTL in milliseconds (1 hour)
export const CACHE_TTL = 3600000;

// Max IPs per batch request
export const BATCH_MAX = 50;
