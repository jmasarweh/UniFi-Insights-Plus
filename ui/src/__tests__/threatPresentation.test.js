import { describe, it, expect } from 'vitest'
import { getThreatLevel, THREAT_LEVELS } from '../lib/threatPresentation'


describe('THREAT_LEVELS', () => {
  it('has 5 tiers in descending min order', () => {
    expect(THREAT_LEVELS).toHaveLength(5)
    for (let i = 1; i < THREAT_LEVELS.length; i++) {
      expect(THREAT_LEVELS[i - 1].min).toBeGreaterThan(THREAT_LEVELS[i].min)
    }
  })

  it('each tier has required fields', () => {
    for (const tier of THREAT_LEVELS) {
      expect(tier).toHaveProperty('min')
      expect(tier).toHaveProperty('label')
      expect(tier).toHaveProperty('color')
      expect(tier).toHaveProperty('dot')
    }
  })
})


describe('getThreatLevel', () => {
  it('returns null for null score', () => {
    expect(getThreatLevel(null)).toBeNull()
  })

  it('returns null for undefined score', () => {
    expect(getThreatLevel(undefined)).toBeNull()
  })

  it('returns Critical for score >= 75', () => {
    expect(getThreatLevel(75).label).toBe('Critical')
    expect(getThreatLevel(100).label).toBe('Critical')
    expect(getThreatLevel(99).label).toBe('Critical')
  })

  it('returns High for score 50-74', () => {
    expect(getThreatLevel(50).label).toBe('High')
    expect(getThreatLevel(74).label).toBe('High')
  })

  it('returns Medium for score 25-49', () => {
    expect(getThreatLevel(25).label).toBe('Medium')
    expect(getThreatLevel(49).label).toBe('Medium')
  })

  it('returns Low for score 1-24', () => {
    expect(getThreatLevel(1).label).toBe('Low')
    expect(getThreatLevel(24).label).toBe('Low')
  })

  it('returns Clean for score 0', () => {
    expect(getThreatLevel(0).label).toBe('Clean')
  })

  it('includes color and dot classes', () => {
    const critical = getThreatLevel(90)
    expect(critical.color).toContain('red')
    expect(critical.dot).toContain('red')

    const clean = getThreatLevel(0)
    expect(clean.color).toContain('emerald')
    expect(clean.dot).toContain('emerald')
  })

  it('boundary: 74 is High, 75 is Critical', () => {
    expect(getThreatLevel(74).label).toBe('High')
    expect(getThreatLevel(75).label).toBe('Critical')
  })

  it('boundary: 49 is Medium, 50 is High', () => {
    expect(getThreatLevel(49).label).toBe('Medium')
    expect(getThreatLevel(50).label).toBe('High')
  })

  it('boundary: 24 is Low, 25 is Medium', () => {
    expect(getThreatLevel(24).label).toBe('Low')
    expect(getThreatLevel(25).label).toBe('Medium')
  })

  it('returns null for NaN', () => {
    expect(getThreatLevel(NaN)).toBeNull()
  })

  it('handles floating-point scores within tier ranges', () => {
    expect(getThreatLevel(24.5).label).toBe('Low')
    expect(getThreatLevel(74.9).label).toBe('High')
    expect(getThreatLevel(49.99).label).toBe('Medium')
  })

  it('negative scores fall through to Clean (AbuseIPDB returns 0-100)', () => {
    expect(getThreatLevel(-1).label).toBe('Clean')
    expect(getThreatLevel(-10).label).toBe('Clean')
  })

  it('coerces string scores via JS comparison', () => {
    expect(getThreatLevel('75').label).toBe('Critical')
    expect(getThreatLevel('0').label).toBe('Clean')
  })
})
