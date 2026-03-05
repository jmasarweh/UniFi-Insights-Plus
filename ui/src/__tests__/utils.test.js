import { describe, it, expect } from 'vitest'
import {
  formatNumber,
  formatServiceName,
  isPrivateIP,
  resolveIpSublines,
  validateInterfaceName,
  getInterfaceColor,
  timeRangeToDays,
  filterVisibleRanges,
  decodeThreatCategories,
} from '../utils'


describe('formatNumber', () => {
  it('formats integers with locale separators', () => {
    const result = formatNumber(1000)
    expect(typeof result).toBe('string')
    // locale-dependent, just verify it's not the dash placeholder
    expect(result).not.toBe('—')
  })

  it('returns dash for null', () => {
    expect(formatNumber(null)).toBe('—')
  })

  it('returns dash for undefined', () => {
    expect(formatNumber(undefined)).toBe('—')
  })
})


describe('formatServiceName', () => {
  it('uppercases normal names', () => {
    expect(formatServiceName('http')).toBe('HTTP')
  })

  it('returns dash for falsy', () => {
    expect(formatServiceName(null)).toBe('—')
    expect(formatServiceName('')).toBe('—')
  })

  it('preserves Unknown', () => {
    expect(formatServiceName('Unknown')).toBe('Unknown')
    expect(formatServiceName('unknown')).toBe('Unknown')
  })
})


describe('isPrivateIP', () => {
  it('detects 10.x.x.x as private', () => {
    expect(isPrivateIP('10.0.0.1')).toBe(true)
  })

  it('detects 192.168.x.x as private', () => {
    expect(isPrivateIP('192.168.1.1')).toBe(true)
  })

  it('detects 172.16-31.x.x as private', () => {
    expect(isPrivateIP('172.16.0.1')).toBe(true)
    expect(isPrivateIP('172.31.255.255')).toBe(true)
  })

  it('rejects 172.15.x.x and 172.32.x.x', () => {
    expect(isPrivateIP('172.15.0.1')).toBe(false)
    expect(isPrivateIP('172.32.0.1')).toBe(false)
  })

  it('detects loopback', () => {
    expect(isPrivateIP('127.0.0.1')).toBe(true)
  })

  it('detects link-local', () => {
    expect(isPrivateIP('169.254.1.1')).toBe(true)
  })

  it('identifies public IPs', () => {
    expect(isPrivateIP('8.8.8.8')).toBe(false)
    expect(isPrivateIP('203.0.113.5')).toBe(false)
  })

  it('returns true for falsy input', () => {
    expect(isPrivateIP(null)).toBe(true)
    expect(isPrivateIP('')).toBe(true)
  })

  // IPv6
  it('detects IPv6 loopback', () => {
    expect(isPrivateIP('::1')).toBe(true)
  })

  it('detects IPv6 ULA', () => {
    expect(isPrivateIP('fd00::1')).toBe(true)
    expect(isPrivateIP('fc00::1')).toBe(true)
  })

  it('detects IPv6 link-local', () => {
    expect(isPrivateIP('fe80::1')).toBe(true)
  })

  it('identifies public IPv6', () => {
    expect(isPrivateIP('2001:db8::1')).toBe(false)
  })
})


describe('resolveIpSublines', () => {
  it('assigns ASN to source for inbound + public src', () => {
    const result = resolveIpSublines({
      asn_name: 'Cloudflare', direction: 'inbound',
      src_ip: '1.1.1.1', dst_ip: '192.168.1.1',
    })
    expect(result.srcSubline).toBe('Cloudflare')
    expect(result.dstSubline).toBeNull()
  })

  it('assigns ASN to destination for outbound + public dst', () => {
    const result = resolveIpSublines({
      asn_name: 'Google', direction: 'outbound',
      src_ip: '192.168.1.1', dst_ip: '8.8.8.8',
    })
    expect(result.srcSubline).toBeNull()
    expect(result.dstSubline).toBe('Google')
  })

  it('returns nulls when no ASN or hostnames', () => {
    const result = resolveIpSublines({
      direction: 'inbound', src_ip: '1.1.1.1', dst_ip: '10.0.0.1',
    })
    expect(result.srcSubline).toBeNull()
    expect(result.dstSubline).toBeNull()
  })

  it('does not assign to private IPs', () => {
    const result = resolveIpSublines({
      asn_name: 'ISP', direction: 'inbound',
      src_ip: '192.168.1.1', dst_ip: '10.0.0.1',
    })
    expect(result.srcSubline).toBeNull()
  })
})


describe('validateInterfaceName', () => {
  it('accepts valid interface names', () => {
    expect(validateInterfaceName('ppp0')).toBeNull()
    expect(validateInterfaceName('eth4')).toBeNull()
    expect(validateInterfaceName('br0')).toBeNull()
  })

  it('accepts VLAN-tagged interfaces', () => {
    expect(validateInterfaceName('eth4.10')).toBeNull()
  })

  it('accepts sfp+0 style', () => {
    expect(validateInterfaceName('sfp+0')).toBeNull()
  })

  it('rejects invalid names', () => {
    expect(validateInterfaceName('123abc')).toBeTruthy()
    expect(validateInterfaceName('')).toBeTruthy()
  })

  it('rejects out-of-range VLAN IDs', () => {
    expect(validateInterfaceName('eth0.0')).toBeTruthy()
    expect(validateInterfaceName('eth0.4095')).toBeTruthy()
  })
})


describe('getInterfaceColor', () => {
  it('returns gray for falsy', () => {
    expect(getInterfaceColor(null)).toBe('text-gray-300')
    expect(getInterfaceColor('')).toBe('text-gray-300')
  })

  it('returns blue for br0/br10', () => {
    expect(getInterfaceColor('br0')).toBe('text-blue-400')
    expect(getInterfaceColor('br10')).toBe('text-blue-400')
  })

  it('returns amber for br20', () => {
    expect(getInterfaceColor('br20')).toBe('text-amber-400')
  })
})


describe('timeRangeToDays', () => {
  it('converts hours', () => {
    expect(timeRangeToDays('24h')).toBe(1)
    expect(timeRangeToDays('6h')).toBe(0.25)
  })

  it('converts days', () => {
    expect(timeRangeToDays('7d')).toBe(7)
    expect(timeRangeToDays('30d')).toBe(30)
  })

  it('returns 0 for invalid', () => {
    expect(timeRangeToDays('')).toBe(0)
    expect(timeRangeToDays(null)).toBe(0)
    expect(timeRangeToDays('abc')).toBe(0)
  })
})


describe('filterVisibleRanges', () => {
  const ranges = ['1h', '6h', '24h', '7d', '30d', '60d']

  it('returns all when no maxFilterDays', () => {
    expect(filterVisibleRanges(ranges, null)).toEqual(ranges)
    expect(filterVisibleRanges(ranges, 0)).toEqual(ranges)
  })

  it('includes ranges up to max plus one ceiling', () => {
    const result = filterVisibleRanges(ranges, 7)
    // 1h, 6h, 24h, 7d fit within 7 days; 30d is ceiling
    expect(result).toContain('7d')
    expect(result).toContain('30d')
    expect(result).not.toContain('60d')
  })

  it('includes sub-day ranges', () => {
    const result = filterVisibleRanges(ranges, 1)
    expect(result).toContain('1h')
    expect(result).toContain('6h')
    expect(result).toContain('24h')
  })
})


describe('decodeThreatCategories', () => {
  it('decodes known category codes', () => {
    expect(decodeThreatCategories([14, 18])).toBe('Port Scan, Brute-Force')
  })

  it('handles blacklist tag', () => {
    expect(decodeThreatCategories(['blacklist'])).toBe('Blacklist')
  })

  it('returns null for empty/falsy', () => {
    expect(decodeThreatCategories(null)).toBeNull()
    expect(decodeThreatCategories([])).toBeNull()
  })

  it('falls back for unknown codes', () => {
    expect(decodeThreatCategories([999])).toBe('Cat 999')
  })
})
