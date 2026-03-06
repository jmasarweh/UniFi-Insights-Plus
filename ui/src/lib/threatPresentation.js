export const THREAT_LEVELS = [
  { min: 75, label: 'Critical', color: 'text-red-400',     dot: 'bg-red-400',     hex: '#f87171' },
  { min: 50, label: 'High',     color: 'text-orange-400',  dot: 'bg-orange-400',  hex: '#fb923c' },
  { min: 25, label: 'Medium',   color: 'text-yellow-400',  dot: 'bg-yellow-400',  hex: '#facc15' },
  { min:  1, label: 'Low',      color: 'text-blue-400',    dot: 'bg-blue-400',    hex: '#60a5fa' },
  { min:  0, label: 'Clean',    color: 'text-emerald-400', dot: 'bg-emerald-400', hex: '#34d399' },
]

export function getThreatLevel(score) {
  if (score === null || score === undefined || Number.isNaN(score)) return null
  return THREAT_LEVELS.find(t => score >= t.min) ?? THREAT_LEVELS[THREAT_LEVELS.length - 1]
}
