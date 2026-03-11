import NetworkBadge from './NetworkBadge'

/**
 * Shared IP address cell renderer.
 * Used by LogTable (log stream) and TopIPPairs (flow view).
 * Shows device name, IP, optional VLAN/network badge, and optional subline (ASN).
 */
export default function IPCell({ ip, port, deviceName, vlan, networkLabel, subline }) {
  if (!ip) return <span className="text-gray-700">—</span>

  const hasBadge = vlan != null || !!networkLabel

  if (deviceName || hasBadge || subline) {
    return (
      <div className="min-w-0 leading-tight">
        {(deviceName || hasBadge) && (
          <div className="flex items-center gap-1">
            {deviceName && <span className="text-gray-200 text-[12px] truncate" title={deviceName}>{deviceName}</span>}
            <NetworkBadge vlan={vlan} vpnBadge={networkLabel} />
          </div>
        )}
        <span className="inline-flex items-baseline gap-0.5 min-w-0 max-w-full">
          <span className={`${deviceName || hasBadge ? 'text-gray-500 text-[11px]' : 'text-gray-300 text-[13px]'} truncate`} title={ip}>{ip}</span>
          {port && <span className={`${deviceName || hasBadge ? 'text-gray-600 text-[11px]' : 'text-gray-500'}`}>:{port}</span>}
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
