import { useState, useEffect, useMemo, useCallback, useRef } from 'react'
import { fetchTechnitiumSettings, updateTechnitiumSettings, testTechnitiumConnection } from '../api'
import InfoTooltip from './InfoTooltip'

const INPUT_CLS = 'w-full px-3 py-1.5 bg-black border border-gray-700 rounded text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-teal-500 focus:ring-2 focus:ring-teal-500/20'

function formatDate(str) {
  const d = new Date(str)
  return isNaN(d.getTime()) ? 'Unknown' : d.toLocaleString()
}

const POLL_INTERVALS = [
  { value: 15, label: '15 seconds' },
  { value: 30, label: '30 seconds' },
  { value: 60, label: '60 seconds' },
  { value: 120, label: '2 minutes' },
  { value: 300, label: '5 minutes' },
]

const ENRICHMENT_OPTIONS = [
  { value: 'none', label: 'None' },
  { value: 'geoip', label: 'GeoIP only' },
  { value: 'threat', label: 'Threat only' },
  { value: 'both', label: 'Both' },
]

let _keySeq = 1
const withKeys = (servers) => (servers || []).map(s => ({
  ...s, token: '', app: s.app || '', cluster: !!s.cluster, _key: s.id || `new-${_keySeq++}`,
}))

export default function SettingsTechnitium() {
  const [settings, setSettings] = useState(null)
  const [draft, setDraft] = useState(null)
  const [saving, setSaving] = useState(false)
  const [saveStatus, setSaveStatus] = useState(null)
  const [testing, setTesting] = useState({})       // _key -> bool
  const [testResults, setTestResults] = useState({}) // _key -> {type,text}
  const [testPassed, setTestPassed] = useState({})  // _key -> bool
  const [appOptions, setAppOptions] = useState({})  // _key -> [app names from last test]
  const [loadError, setLoadError] = useState(null)
  const saveTimerRef = useRef(null)

  const loadSettings = useCallback(async () => {
    try {
      const data = await fetchTechnitiumSettings()
      setSettings(data)
      setLoadError(null)
      setDraft({
        enabled: data.enabled,
        poll_interval: data.poll_interval ?? 60,
        enrichment: data.enrichment || 'both',
        servers: withKeys(data.servers),
      })
    } catch (e) {
      console.error('Failed to load Technitium settings:', e)
      setLoadError(e.message || 'Failed to load settings')
    }
  }, [])

  useEffect(() => { loadSettings() }, [loadSettings])
  useEffect(() => () => { if (saveTimerRef.current) clearTimeout(saveTimerRef.current) }, [])

  const updateServer = (key, patch) => setDraft(d => ({
    ...d,
    servers: d.servers.map(s => s._key === key ? { ...s, ...patch } : s),
  }))

  const addServer = () => setDraft(d => ({
    ...d,
    servers: [...d.servers, { _key: `new-${_keySeq++}`, name: '', host: '', token: '', verify_tls: true, app: '', cluster: false, token_set: false }],
  }))

  const removeServer = (key) => setDraft(d => ({
    ...d,
    servers: d.servers.filter(s => s._key !== key),
  }))

  const hasChanges = useMemo(() => {
    if (!settings || !draft) return false
    if (draft.enabled !== settings.enabled) return true
    if (draft.poll_interval !== settings.poll_interval) return true
    if (draft.enrichment !== settings.enrichment) return true
    const orig = settings.servers || []
    if (draft.servers.length !== orig.length) return true
    return draft.servers.some(s => {
      const o = orig.find(x => x.id === s.id)
      if (!o) return true // newly added
      return s.host !== o.host || s.name !== o.name || s.verify_tls !== o.verify_tls
        || (s.app || '') !== (o.app || '') || !!s.cluster !== !!o.cluster || !!s.token
    })
  }, [settings, draft])

  // A server is "usable" if it has a saved token or a freshly-tested one
  const serverUsable = (s) => (s.token_set || testPassed[s._key]) && !!s.host
  const canSave = useMemo(() => {
    if (!draft || !hasChanges || saving) return false
    if (draft.servers.some(s => !s.host)) return false
    if (draft.enabled && !draft.servers.some(serverUsable)) return false
    return true
  }, [draft, hasChanges, saving, testPassed])

  async function handleTest(server) {
    setTesting(t => ({ ...t, [server._key]: true }))
    setTestResults(r => ({ ...r, [server._key]: null }))
    try {
      const result = await testTechnitiumConnection({
        id: server.id, host: server.host, token: server.token, verify_tls: server.verify_tls,
        app: server.app || '', cluster: !!server.cluster,
      })
      if (Array.isArray(result.apps)) {
        setAppOptions(a => ({ ...a, [server._key]: result.apps }))
      }
      if (!result.success) {
        setTestResults(r => ({ ...r, [server._key]: { type: 'error', text: result.error || 'Connection failed' } }))
        setTestPassed(p => ({ ...p, [server._key]: false }))
      } else {
        const nodes = Array.isArray(result.cluster_nodes) ? result.cluster_nodes : null
        const nodeText = nodes ? ` — cluster: ${nodes.map(n => n.name).join(', ')}` : ''
        setTestResults(r => ({ ...r, [server._key]: {
          type: 'success',
          text: result.backend
            ? `Connected — ${result.backend}${typeof result.total_queries === 'number' ? `, ${result.total_queries.toLocaleString()} queries` : ''}${nodeText}`
            : 'Connection successful',
        } }))
        setTestPassed(p => ({ ...p, [server._key]: true }))
      }
    } catch (e) {
      setTestResults(r => ({ ...r, [server._key]: { type: 'error', text: e.message } }))
    } finally {
      setTesting(t => ({ ...t, [server._key]: false }))
    }
  }

  async function handleSave() {
    setSaving(true)
    setSaveStatus(null)
    try {
      await updateTechnitiumSettings({
        enabled: draft.enabled,
        poll_interval: draft.poll_interval,
        enrichment: draft.enrichment,
        servers: draft.servers
          .filter(s => !s.env_managed)
          .map(s => ({
            ...(s.id ? { id: s.id } : {}),
            name: s.name || s.host,
            host: s.host,
            verify_tls: s.verify_tls,
            app: s.app || '',
            cluster: !!s.cluster,
            ...(s.token ? { token: s.token } : {}),
          })),
      })
      setSaveStatus({ type: 'saved', text: 'Settings saved' })
      if (saveTimerRef.current) clearTimeout(saveTimerRef.current)
      saveTimerRef.current = setTimeout(() => setSaveStatus(null), 3000)
      setTestPassed({})
      await loadSettings()
    } catch (e) {
      setSaveStatus({ type: 'error', text: e.message })
    } finally {
      setSaving(false)
    }
  }

  if (loadError) {
    return (
      <div className="text-sm text-red-400">
        Failed to load Technitium settings: {loadError}
        <button onClick={loadSettings} className="ml-2 text-teal-400 hover:text-teal-300">Retry</button>
      </div>
    )
  }
  if (!draft) {
    return <div className="text-sm text-gray-400">Loading Technitium settings...</div>
  }

  return (
    <div className="space-y-8">
      <section>
        <h2 className="flex items-center gap-2 text-base font-semibold text-gray-300 mb-3 uppercase tracking-wider">
          <svg className="w-5 h-5 text-teal-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
              d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          Technitium DNS
        </h2>
        <p className="text-sm text-gray-500 mb-3">
          Ingest DNS queries from one or more Technitium DNS Servers. The Query Logs backend
          (Sqlite, MySQL, MariaDB, or PostgreSQL) is detected automatically per server, or pick
          a specific app when several are installed. For a Technitium cluster, add just one
          node and enable cluster polling to pull every node's logs through it.
        </p>

        <div className="rounded-lg border border-gray-700 bg-gray-950">
          <div className="p-5 space-y-5">
            {/* Master enable */}
            <div className="flex items-center justify-between">
              <div>
                <p className="text-base text-gray-200 font-medium">Enable Technitium</p>
                <p className="text-sm text-gray-500">Poll all configured servers below for DNS query logs.</p>
              </div>
              <button
                onClick={() => {
                  if (draft.enabled) setDraft(d => ({ ...d, enabled: false }))
                  else if (draft.servers.some(serverUsable)) setDraft(d => ({ ...d, enabled: true }))
                }}
                disabled={!draft.enabled && !draft.servers.some(serverUsable)}
                className={`px-3 py-1 rounded text-sm font-semibold border transition-colors ${
                  draft.enabled
                    ? 'bg-green-500/10 text-green-300 border-green-500/40'
                    : !draft.servers.some(serverUsable)
                      ? 'bg-black text-gray-600 border-gray-800 cursor-not-allowed'
                      : 'bg-black text-gray-400 border-gray-700'
                }`}
              >
                {draft.enabled ? 'Enabled' : 'Disabled'}
              </button>
            </div>

            {/* Servers */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <label className="text-sm font-medium text-gray-200">Servers</label>
                <button
                  onClick={addServer}
                  className="px-2.5 py-1 rounded text-sm font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors"
                >
                  + Add server
                </button>
              </div>

              {draft.servers.length === 0 && (
                <p className="text-sm text-gray-500">No servers configured. Add one to begin ingesting DNS logs.</p>
              )}

              {draft.servers.map((s) => {
                const st = settings?.servers?.find(x => x.id === s.id)?.status
                const result = testResults[s._key]
                return (
                  <div key={s._key} className="rounded-lg border border-gray-800 bg-black/40 p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 min-w-0">
                        {st && (
                          <span className={`w-1.5 h-1.5 rounded-full block shrink-0 ${st.connected ? 'bg-emerald-400' : draft.enabled ? 'bg-red-400' : 'bg-gray-500'}`} />
                        )}
                        <span className="text-sm font-medium text-gray-200 truncate">{s.name || s.host || 'New server'}</span>
                        {s.backend && <span className="text-xs text-gray-500 shrink-0">({s.backend})</span>}
                        {s.env_managed && <span className="text-xs text-blue-300 shrink-0">env</span>}
                      </div>
                      {!s.env_managed && (
                        <button onClick={() => removeServer(s._key)} className="text-sm text-gray-500 hover:text-red-400 shrink-0">Remove</button>
                      )}
                    </div>
                    {st?.last_poll && (
                      <div className="text-xs text-gray-500 -mt-1">Last poll: {formatDate(st.last_poll)}{st.last_error ? ` — ${st.last_error}` : ''}</div>
                    )}
                    {st?.nodes && (
                      <div className="flex flex-wrap gap-x-3 gap-y-1 -mt-1">
                        {Object.entries(st.nodes).map(([node, ns]) => (
                          <span key={node} className="flex items-center gap-1 text-xs text-gray-500" title={ns.last_error || ''}>
                            <span className={`w-1.5 h-1.5 rounded-full block ${ns.connected ? 'bg-emerald-400' : 'bg-red-400'}`} />
                            {node}
                          </span>
                        ))}
                      </div>
                    )}

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <div>
                        <label className="text-xs text-gray-400 block mb-1">Name</label>
                        <input type="text" value={s.name || ''} disabled={s.env_managed}
                          onChange={e => updateServer(s._key, { name: e.target.value })}
                          placeholder="dns-01" className={INPUT_CLS} />
                      </div>
                      <div>
                        <label className="text-xs text-gray-400 block mb-1">URL</label>
                        <input type="text" value={s.host || ''} disabled={s.env_managed}
                          onChange={e => { updateServer(s._key, { host: e.target.value }); setTestPassed(p => ({ ...p, [s._key]: false })) }}
                          placeholder="http://10.0.40.2:5380" className={INPUT_CLS} />
                      </div>
                    </div>

                    <div>
                      <label className="flex items-center gap-1 text-xs text-gray-400 mb-1">
                        API Token
                        <InfoTooltip>
                          <p>Create a non-expiring token in Technitium: <strong className="text-blue-300">Administration &gt; Sessions &gt; Create Token</strong>, with access to the Query Logs app.</p>
                        </InfoTooltip>
                      </label>
                      <input type="password" value={s.token || ''} disabled={s.env_managed}
                        onChange={e => { updateServer(s._key, { token: e.target.value }); setTestPassed(p => ({ ...p, [s._key]: false })) }}
                        placeholder={s.token_set ? '(saved, leave blank to keep)' : 'Technitium API token'} className={INPUT_CLS} />
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <div>
                        <label className="flex items-center gap-1 text-xs text-gray-400 mb-1">
                          Query Logs App
                          <InfoTooltip>
                            <p>Which Query Logs app to poll when more than one is installed (e.g. both Sqlite and PostgreSQL backends). <strong className="text-blue-300">Auto-detect</strong> uses the first one found. Run <strong className="text-blue-300">Test</strong> to populate this list from the server.</p>
                          </InfoTooltip>
                        </label>
                        <select value={s.app || ''} disabled={s.env_managed}
                          onChange={e => updateServer(s._key, { app: e.target.value })}
                          className={INPUT_CLS}>
                          <option value="">Auto-detect</option>
                          {[...new Set([...(appOptions[s._key] || []), ...(s.app ? [s.app] : [])])].map(name => (
                            <option key={name} value={name}>{name}</option>
                          ))}
                        </select>
                      </div>
                      <div className="flex items-end pb-1.5">
                        <label className="flex items-center gap-2 cursor-pointer">
                          <input type="checkbox" checked={!!s.cluster} disabled={s.env_managed}
                            onChange={e => { updateServer(s._key, { cluster: e.target.checked }); setTestPassed(p => ({ ...p, [s._key]: false })) }}
                            className="w-4 h-4 rounded border-gray-600 bg-black text-teal-500 focus:ring-teal-500/40" />
                          <span className="text-sm text-gray-300">Poll entire cluster</span>
                          <InfoTooltip>
                            <p>Pull query logs from <strong className="text-blue-300">every node</strong> of this server's Technitium cluster through this one server (Technitium 14+ with Clustering initialized). The token needs <strong className="text-blue-300">Administration: View</strong> permission. Each node keeps its own cursor.</p>
                          </InfoTooltip>
                        </label>
                      </div>
                    </div>

                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input type="checkbox" checked={s.verify_tls !== false} disabled={s.env_managed}
                          onChange={e => { updateServer(s._key, { verify_tls: e.target.checked }); setTestPassed(p => ({ ...p, [s._key]: false })) }}
                          className="w-4 h-4 rounded border-gray-600 bg-black text-teal-500 focus:ring-teal-500/40" />
                        <span className="text-sm text-gray-300">Verify TLS</span>
                        <InfoTooltip>
                          <p>Keep enabled for valid HTTPS certs. Uncheck only for a self-signed cert on a trusted network. Not needed for plain http:// URLs.</p>
                        </InfoTooltip>
                      </label>
                      <div className="flex items-center gap-3">
                        {result?.type === 'success' && <span className="text-sm text-emerald-400">{result.text}</span>}
                        <button onClick={() => handleTest(s)} disabled={testing[s._key] || !s.host || s.env_managed}
                          className="px-3 py-1.5 rounded text-sm font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
                          {testing[s._key] ? 'Testing...' : 'Test'}
                        </button>
                      </div>
                    </div>
                    {result?.type === 'error' && (
                      <div className="flex items-start gap-2 bg-yellow-500/10 border border-yellow-500/30 rounded px-3 py-2">
                        <svg className="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                          <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 6a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 6zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
                        </svg>
                        <span className="text-sm text-yellow-200">{result.text}</span>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>

            {/* Poll interval */}
            <div>
              <label className="flex items-center gap-1 text-sm font-medium text-gray-200 mb-1">
                Poll Interval
                <InfoTooltip>
                  <p>How often to fetch new DNS queries from each server. Lower intervals capture more queries but increase load.</p>
                </InfoTooltip>
              </label>
              <select value={draft.poll_interval ?? 60}
                onChange={e => setDraft(d => ({ ...d, poll_interval: parseInt(e.target.value, 10) }))}
                className={INPUT_CLS}>
                {POLL_INTERVALS.map(opt => <option key={opt.value} value={opt.value}>{opt.label}</option>)}
              </select>
            </div>

            {/* Enrichment */}
            <div>
              <label className="text-sm font-medium text-gray-200 block mb-1">Enrichment</label>
              <select value={draft.enrichment || 'both'}
                onChange={e => setDraft(d => ({ ...d, enrichment: e.target.value }))}
                className={INPUT_CLS}>
                {ENRICHMENT_OPTIONS.map(opt => <option key={opt.value} value={opt.value}>{opt.label}</option>)}
              </select>
              <p className="text-sm text-gray-500 mt-1">Apply GeoIP and/or threat score enrichment to resolved DNS answer IPs.</p>
            </div>
          </div>

          <div className="border-t border-gray-800" />

          {/* Save footer */}
          <div className="px-5 py-3 flex items-center justify-between">
            <div className="flex items-center gap-3">
              {saveStatus?.type === 'saved' && <span className="text-sm text-emerald-400">{saveStatus.text}</span>}
              {saveStatus?.type === 'error' && <span className="text-sm text-red-400">{saveStatus.text}</span>}
            </div>
            <button onClick={handleSave} disabled={!canSave}
              className={`px-3 py-1.5 rounded text-sm font-medium transition-colors ${
                canSave ? 'bg-teal-600 hover:bg-teal-500 text-white' : 'bg-gray-800 text-gray-500 cursor-not-allowed'
              }`}>
              {saving ? 'Saving...' : 'Save'}
            </button>
          </div>
        </div>
      </section>
    </div>
  )
}
