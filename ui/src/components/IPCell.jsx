/**
 * Shared IP address cell renderer.
 * Used by LogTable (log stream) and TopIPPairs (flow view).
 * Shows device name, IP, optional VLAN/network badge, and optional subline (ASN).
 */
export default function IPCell({ ip, port, deviceName, vlan, networkLabel, subline }) {
  if (!ip) return <span className="text-gray-700">—</span>

  const badge = vlan != null ? (
    <span className="text-[10px] px-1 py-0 rounded bg-violet-500/15 text-violet-400 border border-violet-500/30 shrink-0">
      VLAN {vlan}
    </span>
  ) : networkLabel ? (
    <span className="text-[10px] px-1 py-0 rounded bg-teal-500/15 text-teal-400 border border-teal-500/30 shrink-0">
      {networkLabel}
    </span>
  ) : null

  if (deviceName || badge || subline) {
    return (
      <div className="min-w-0 leading-tight">
        {(deviceName || badge) && (
          <div className="flex items-center gap-1">
            {deviceName && <span className="text-gray-200 text-[12px] truncate" title={deviceName}>{deviceName}</span>}
            {badge}
          </div>
        )}
        <span className="inline-flex items-baseline gap-0.5 min-w-0 max-w-full">
          <span className={`${deviceName || badge ? 'text-gray-500 text-[11px]' : 'text-gray-300 text-[13px]'} truncate`} title={ip}>{ip}</span>
          {port && <span className={`${deviceName || badge ? 'text-gray-600 text-[11px]' : 'text-gray-500'}`}>:{port}</span>}
        </span>
        {subline && <div className="text-[11px] text-gray-500 truncate" title={subline}>{subline}</div>}
      </div>
    )
  }

  return (
    <span className="inline-flex items-baseline gap-0.5 min-w-0 max-w-full">
      <span className="text-gray-300 truncate" title={ip}>{ip}</span>
      {port && <span className="text-gray-500">:{port}</span>}
    </span>
  )
}
