import { describe, it, expect } from 'vitest'
import {
  isVpnInterface,
  suggestVpnType,
  getIfaceDescription,
  generateVpnInterface,
  getMismatchWarning,
  VPN_PREFIXES,
  VPN_PREFIX_BADGES,
  BADGE_TO_PREFIX,
  BADGE_CHOICES,
} from '../vpnUtils'


describe('isVpnInterface', () => {
  it('detects WireGuard server interfaces', () => {
    expect(isVpnInterface('wgsrv0')).toBe(true)
    expect(isVpnInterface('wgsrv1')).toBe(true)
  })

  it('detects WireGuard client interfaces', () => {
    expect(isVpnInterface('wgclt0')).toBe(true)
  })

  it('detects other VPN types', () => {
    expect(isVpnInterface('tun0')).toBe(true)
    expect(isVpnInterface('vti0')).toBe(true)
    expect(isVpnInterface('l2tp0')).toBe(true)
    expect(isVpnInterface('tlprt0')).toBe(true)
  })

  it('rejects non-VPN interfaces', () => {
    expect(isVpnInterface('eth0')).toBe(false)
    expect(isVpnInterface('br0')).toBe(false)
    expect(isVpnInterface('ppp0')).toBe(false)
  })
})


describe('suggestVpnType', () => {
  it('maps wgsrv to WGD SRV', () => {
    expect(suggestVpnType('wgsrv0')).toBe('WGD SRV')
  })

  it('maps wgclt to WGD CLT', () => {
    expect(suggestVpnType('wgclt0')).toBe('WGD CLT')
  })

  it('maps tlprt to TELEPORT', () => {
    expect(suggestVpnType('tlprt0')).toBe('TELEPORT')
  })

  it('returns empty string for unknown', () => {
    expect(suggestVpnType('eth0')).toBe('')
  })
})


describe('getIfaceDescription', () => {
  it('returns description for wgsrv', () => {
    expect(getIfaceDescription('wgsrv0')).toBe('WireGuard Server')
  })

  it('returns description for vti', () => {
    expect(getIfaceDescription('vti0')).toBe('Site-to-Site IPsec')
  })

  it('returns null for non-VPN', () => {
    expect(getIfaceDescription('eth0')).toBeNull()
  })
})


describe('generateVpnInterface', () => {
  it('generates first available name', () => {
    expect(generateVpnInterface('WGD SRV', [])).toBe('wgsrv0')
    expect(generateVpnInterface('WGD CLT', [])).toBe('wgclt0')
  })

  it('skips existing interfaces', () => {
    expect(generateVpnInterface('WGD SRV', ['wgsrv0'])).toBe('wgsrv1')
    expect(generateVpnInterface('WGD SRV', ['wgsrv0', 'wgsrv1'])).toBe('wgsrv2')
  })

  it('returns null for unknown badge', () => {
    expect(generateVpnInterface('INVALID', [])).toBeNull()
  })
})


describe('getMismatchWarning', () => {
  it('warns when wgsrv interface has WGD CLT type', () => {
    const warning = getMismatchWarning('wgsrv0', 'WGD CLT')
    expect(warning).toContain('WireGuard Server')
  })

  it('warns when wgclt interface has WGD SRV type', () => {
    const warning = getMismatchWarning('wgclt0', 'WGD SRV')
    expect(warning).toContain('WireGuard Client')
  })

  it('returns null for correct mapping', () => {
    expect(getMismatchWarning('wgsrv0', 'WGD SRV')).toBeNull()
    expect(getMismatchWarning('wgclt0', 'WGD CLT')).toBeNull()
  })

  it('returns null for non-conflicting types', () => {
    expect(getMismatchWarning('tun0', 'OVPN TUN')).toBeNull()
  })

  it('returns null when no VPN type', () => {
    expect(getMismatchWarning('wgsrv0', null)).toBeNull()
  })
})


describe('constants consistency', () => {
  it('all VPN_PREFIX_BADGES keys are in VPN_PREFIXES', () => {
    for (const prefix of Object.keys(VPN_PREFIX_BADGES)) {
      expect(VPN_PREFIXES).toContain(prefix)
    }
  })

  it('all BADGE_CHOICES have a reverse mapping in BADGE_TO_PREFIX', () => {
    for (const badge of BADGE_CHOICES) {
      expect(BADGE_TO_PREFIX).toHaveProperty(badge)
    }
  })
})
