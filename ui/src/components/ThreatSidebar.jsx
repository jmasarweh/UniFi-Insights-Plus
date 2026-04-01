import { useState, useEffect } from 'react'
import { fetchLogsBatch } from '../api'
import { FlagIcon, decodeThreatCategories, getInterfaceName, formatServiceName, normalizeRuleDesc } from '../utils'
import { getThreatLevel } from '../lib/threatPresentation'

const ACTION_STYLES = {
  block: 'text-red-400',
  allow: 'text-emerald-400',
  redirect: 'text-yellow-400',
}

function ThreatBadge({ score }) {
  const level = getThreatLevel(score)
  if (!level) return null
  return <span className={`${level.color} font-medium`}>{score}</span>
}

function Section({ title, open, onToggle, children }) {
  return (
    <div className="border-t border-gray-800/50">
      <button
        onClick={onToggle}
        className="w-full flex items-center justify-between px-3 py-2 text-xs uppercase tracking-wider text-gray-400 hover:text-gray-300"
      >
        {title}
        <svg className={`w-3.5 h-3.5 transition-transform ${open ? '' : '-rotate-90'}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && <div className="px-3 pb-2">{children}</div>}
    </div>
  )
}

function Row({ label, value }) {
  if (!value) return null
  return (
    <div className="flex justify-between items-baseline gap-2 py-0.5">
      <span className="text-gray-500 text-xs shrink-0">{label}</span>
      <span className="text-gray-200 text-xs text-right truncate">{value}</span>
    </div>
  )
}

function LogEntry({ log, onSelect }) {
  const remote = log.remote_ip || (log.direction === 'inbound' ? log.src_ip : (log.dst_ip || log.src_ip))
  const device = log.direction === 'inbound'
    ? (log.src_device_name || log.rdns || remote)
    : (log.dst_device_name || log.rdns || remote)
  const ts = log.timestamp ? new Date(log.timestamp) : null
  const timeStr = ts
    ? ts.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : ''
  const dateStr = ts
    ? ts.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' })
    : ''

  return (
    <button
      onClick={onSelect}
      className="w-full text-left px-3 py-2 border-b border-gray-800/50 transition-colors hover:bg-gray-800/30"
    >
      <div className="flex items-center justify-between gap-2">
        <span className="text-gray-200 text-xs truncate flex-1" title={remote}>
          {device}
        </span>
        <ThreatBadge score={log.threat_score} />
      </div>
      <div className="flex items-center justify-between gap-2 mt-0.5">
        <span className={`text-xs uppercase font-semibold ${ACTION_STYLES[log.rule_action] || 'text-gray-500'}`}>
          {log.rule_action || (log.log_type === 'firewall' ? 'unknown' : log.log_type)}
        </span>
        <span className="text-gray-500 text-xs">{dateStr} {timeStr}</span>
      </div>
    </button>
  )
}

function LogDetailPanel({ log }) {
  const [openSections, setOpenSections] = useState({ source: true, dest: true, threat: true, traffic: false })
  const toggle = (key) => setOpenSections(prev => ({ ...prev, [key]: !prev[key] }))

  const categories = decodeThreatCategories(log.threat_categories)

  return (
    <div className="overflow-y-auto flex-1 scrollbar-thin">
      {/* Header */}
      <div className="px-3 py-2 text-xs text-gray-500">
        {log.timestamp && new Date(log.timestamp).toLocaleString('en-GB', {
          day: '2-digit', month: 'short', year: 'numeric',
          hour: '2-digit', minute: '2-digit', second: '2-digit'
        })}
      </div>

      {/* Threat overview */}
      {log.threat_score != null && (
        <div className="px-3 pb-2">
          <Row label="Risk" value={<ThreatBadge score={log.threat_score} />} />
          <Row label="Action" value={
            <span className={ACTION_STYLES[log.rule_action] || 'text-gray-500'}>
              {log.rule_action || (log.log_type === 'firewall' ? 'unknown' : '—')}
            </span>
          } />
          {log.service_name && <Row label="Service" value={formatServiceName(log.service_name)} />}
          {log.rule_desc && <Row label="Policy" value={normalizeRuleDesc(log.rule_desc)} />}
          <Row label="Direction" value={log.direction} />
        </div>
      )}

      {/* Source section */}
      <Section title="Source" open={openSections.source} onToggle={() => toggle('source')}>
        {log.src_device_name && <Row label="Client" value={log.src_device_name} />}
        <Row label="IP Address" value={log.src_ip} />
        {log.src_port && <Row label="Port" value={log.src_port} />}
        {log.rdns && log.direction === 'inbound' && <Row label="rDNS" value={log.rdns} />}
      </Section>

      {/* Destination section */}
      <Section title="Destination" open={openSections.dest} onToggle={() => toggle('dest')}>
        {log.dst_device_name && <Row label="Client" value={log.dst_device_name} />}
        <Row label="IP Address" value={log.dst_ip} />
        {log.dst_port && <Row label="Port" value={log.dst_port} />}
        {log.geo_country && (
          <Row label="Region" value={
            <span className="inline-flex items-center gap-1">
              <FlagIcon code={log.geo_country} />
              {[log.geo_city, log.geo_country].filter(Boolean).join(', ')}
            </span>
          } />
        )}
        {log.rdns && log.direction !== 'inbound' && <Row label="rDNS" value={log.rdns} />}
      </Section>

      {/* Threat Intel section */}
      {(log.threat_score != null || categories) && (
        <Section title="Threat Intel" open={openSections.threat} onToggle={() => toggle('threat')}>
          {log.threat_score != null && <Row label="Score" value={`${log.threat_score}%`} />}
          {categories && <Row label="Categories" value={
            <span className="text-purple-400/70">{categories}</span>
          } />}
          {log.abuse_usage_type && <Row label="Usage Type" value={log.abuse_usage_type} />}
          {log.abuse_hostnames && <Row label="Hostnames" value={log.abuse_hostnames} />}
          {log.abuse_total_reports > 0 && <Row label="Reports" value={log.abuse_total_reports.toLocaleString()} />}
          {log.abuse_is_tor && <Row label="Tor Node" value={<span className="text-orange-400">Yes</span>} />}
        </Section>
      )}

      {/* Traffic Info section */}
      <Section title="Traffic Info" open={openSections.traffic} onToggle={() => toggle('traffic')}>
        {log.protocol && <Row label="Protocol" value={log.protocol.toUpperCase()} />}
        {log.interface_in && <Row label="Interface In" value={getInterfaceName(log.interface_in)} />}
        {log.interface_out && <Row label="Interface Out" value={getInterfaceName(log.interface_out)} />}
        {log.rule_name && <Row label="Rule" value={log.rule_name} />}
        {log.asn_name && <Row label="ASN" value={log.asn_name} />}
        {log.service_description && <Row label="Service Info" value={log.service_description} />}
      </Section>
    </div>
  )
}

export default function ThreatSidebar({ location, onClose }) {
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(false)
  const [selectedId, setSelectedId] = useState(null)

  useEffect(() => {
    if (!location?.logIds?.length) { setLogs([]); return }
    let cancelled = false
    setLoading(true)
    setSelectedId(null)
    fetchLogsBatch(location.logIds)
      .then(data => { if (!cancelled) setLogs(data) })
      .catch(() => { if (!cancelled) setLogs([]) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [location])

  const selectedLog = selectedId != null ? logs.find(l => l.id === selectedId) : null

  return (
    <div className="threat-sidebar flex flex-col bg-gray-950 border-l border-gray-800 h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2 border-b border-gray-800 shrink-0">
        <div className="min-w-0">
          <div className="text-sm font-medium text-gray-200 truncate">
            {location ? [location.city, location.country].filter(Boolean).join(', ') : ''}
          </div>
          <div className="text-xs text-gray-500">
            {location?.count} events · {location?.uniqueIps} IPs
          </div>
        </div>
        <button
          onClick={onClose}
          className="text-gray-500 hover:text-gray-300 p-1 shrink-0"
          title="Close"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      {loading && (
        <div className="flex-1 flex items-center justify-center">
          <span className="text-blue-400 text-xs">Loading events...</span>
        </div>
      )}

      {!loading && logs.length === 0 && (
        <div className="flex-1 flex items-center justify-center">
          <span className="text-gray-500 text-xs">No events found</span>
        </div>
      )}

      {!loading && logs.length > 0 && (
        selectedLog ? (
          <div className="flex flex-col flex-1 min-h-0">
            {/* Back to list */}
            <button
              onClick={() => setSelectedId(null)}
              className="flex items-center gap-1 px-3 py-1.5 text-xs text-gray-400 hover:text-gray-200 border-b border-gray-800/50 shrink-0"
            >
              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
              Back to list
            </button>
            <LogDetailPanel log={selectedLog} />
          </div>
        ) : (
          <div className="flex-1 overflow-y-auto scrollbar-thin">
            {logs.map(log => (
              <LogEntry
                key={log.id}
                log={log}
                onSelect={() => setSelectedId(log.id)}
              />
            ))}
          </div>
        )
      )}
    </div>
  )
}
