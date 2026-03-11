const SIZE = {
  xs:  'text-[10px]',
  sm:  'text-xs',
}

export default function NetworkBadge({ vlan, vpnBadge, size = 'xs', className = '' }) {
  if (vlan != null) {
    return (
      <span className={`${SIZE[size]} px-1 py-0 rounded bg-violet-500/15 text-violet-400 border border-violet-500/30 shrink-0 ${className}`}>
        VLAN {vlan}
      </span>
    )
  }
  if (vpnBadge) {
    return (
      <span className={`${SIZE[size]} px-1 py-0 rounded bg-teal-500/15 text-teal-400 border border-teal-500/30 shrink-0 ${className}`}>
        {vpnBadge}
      </span>
    )
  }
  return null
}
