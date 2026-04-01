import { useState, useEffect, useMemo } from 'react'
import { TR_KEY, timeRangeToDays, filterVisibleRanges } from '../utils'

const TIME_RANGES = ['1h', '6h', '24h', '7d', '30d', '60d', '90d', '180d', '365d']

export default function useTimeRange(maxFilterDays) {
  const [timeRange, setTimeRangeState] = useState(() => {
    try { return sessionStorage.getItem(TR_KEY) || '24h' }
    catch { return '24h' }
  })

  const setTimeRange = (tr) => {
    setTimeRangeState(tr)
    try { sessionStorage.setItem(TR_KEY, tr) }
    catch { /* private browsing */ }
  }

  const visibleRanges = useMemo(() => filterVisibleRanges(TIME_RANGES, maxFilterDays), [maxFilterDays])

  // Auto-correct selected range if it exceeds visible ranges (respects ceiling).
  // Depends on [maxFilterDays] only — including visibleRanges/timeRange would
  // create an infinite loop (effect sets timeRange → re-render → new array ref → repeat).
  useEffect(() => {
    if (maxFilterDays == null || visibleRanges.length === 0) return
    if (visibleRanges.includes(timeRange)) return
    const largest = visibleRanges.findLast(tr => timeRangeToDays(tr) >= 1) || visibleRanges[visibleRanges.length - 1]
    if (largest && largest !== timeRange) setTimeRange(largest)
  }, [maxFilterDays]) // eslint-disable-line react-hooks/exhaustive-deps

  return [timeRange, setTimeRange, visibleRanges]
}
