import { useCallback, useEffect, useState } from 'react'
import { fetchAuthStatus, fetchAuthMe, authChangePassword, authSetup, updateSessionTtl } from '../api'

const INPUT_CLS = 'w-full px-3 py-1.5 bg-gray-900 border border-gray-700 rounded text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-teal-500'

export default function SettingsSecurity({ onAuthEnabled }) {
  const [authStatus, setAuthStatus] = useState(null)
  const [me, setMe] = useState(null)
  const [loading, setLoading] = useState(true)

  // Change password
  const [showPwChange, setShowPwChange] = useState(false)
  const [currentPw, setCurrentPw] = useState('')
  const [newPw, setNewPw] = useState('')
  const [confirmPw, setConfirmPw] = useState('')
  const [pwSaving, setPwSaving] = useState(false)
  const [pwStatus, setPwStatus] = useState(null) // { type: 'saved'|'error', text }

  // Enable auth (first-user setup)
  const [setupUser, setSetupUser] = useState('admin')
  const [setupPw, setSetupPw] = useState('')
  const [setupConfirm, setSetupConfirm] = useState('')
  const [setupSaving, setSetupSaving] = useState(false)
  const [setupStatus, setSetupStatus] = useState(null) // { type: 'saved'|'error', text }

  // Session duration
  const [sessionTtl, setSessionTtl] = useState(168)
  const [ttlSaving, setTtlSaving] = useState(false)
  const [ttlStatus, setTtlStatus] = useState(null) // 'saved' | 'error'

  const reload = useCallback(async function reload() {
    setLoading(true)
    try {
      const [status, meResp] = await Promise.allSettled([
        fetchAuthStatus(),
        fetchAuthMe(),
      ])
      if (status.status === 'fulfilled') {
        setAuthStatus(status.value)
        if (status.value.session_ttl_hours) setSessionTtl(status.value.session_ttl_hours)
      }
      if (meResp.status === 'fulfilled') setMe(meResp.value)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { reload() }, [reload])

  async function handleChangePassword(e) {
    e.preventDefault()
    setPwStatus(null)
    if (newPw !== confirmPw) { setPwStatus({ type: 'error', text: 'Passwords do not match' }); return }
    if (newPw.length < 8) { setPwStatus({ type: 'error', text: 'Password must be at least 8 characters' }); return }
    setPwSaving(true)
    try {
      await authChangePassword(currentPw, newPw)
      setPwStatus({ type: 'saved', text: 'Password changed' })
      setShowPwChange(false)
      setCurrentPw('')
      setNewPw('')
      setConfirmPw('')
    } catch (err) {
      setPwStatus({ type: 'error', text: err.message || 'Failed to change password' })
    } finally {
      setPwSaving(false)
    }
  }

  async function handleEnableAuth(e) {
    e.preventDefault()
    setSetupStatus(null)
    if (setupPw !== setupConfirm) { setSetupStatus({ type: 'error', text: 'Passwords do not match' }); return }
    if (setupPw.length < 8) { setSetupStatus({ type: 'error', text: 'Password must be at least 8 characters' }); return }
    if (!setupUser.trim()) { setSetupStatus({ type: 'error', text: 'Username is required' }); return }
    setSetupSaving(true)
    try {
      await authSetup(setupUser.trim(), setupPw)
      setSetupUser('')
      setSetupPw('')
      setSetupConfirm('')
      onAuthEnabled?.()
      reload()
    } catch (err) {
      setSetupStatus({ type: 'error', text: err.message || 'Setup failed' })
    } finally {
      setSetupSaving(false)
    }
  }

  async function handleSaveSessionTtl() {
    setTtlSaving(true)
    setTtlStatus(null)
    try {
      await updateSessionTtl(sessionTtl)
      setAuthStatus(prev => ({ ...prev, session_ttl_hours: sessionTtl }))
      setTtlStatus('saved')
    } catch (err) {
      console.error('Failed to save session TTL:', err)
      setTtlStatus('error')
    } finally {
      setTtlSaving(false)
    }
  }

  function handleCancelPwChange() {
    setShowPwChange(false)
    setCurrentPw('')
    setNewPw('')
    setConfirmPw('')
    setPwStatus(null)
  }

  if (loading) return (
    <div className="space-y-8 animate-pulse">
      <div>
        <div className="h-5 w-40 bg-gray-800 rounded mb-3" />
        <div className="rounded-lg border border-gray-700 bg-gray-950 p-5 space-y-3">
          <div className="h-4 w-56 bg-gray-800 rounded" />
          <div className="h-4 w-36 bg-gray-800 rounded" />
        </div>
      </div>
    </div>
  )

  const authEnabled = authStatus?.auth_enabled_effective

  return (
    <div className="space-y-8">
      <section>
        <h2 className="text-base font-semibold text-gray-300 mb-3 uppercase tracking-wider">Authentication</h2>
        <div className="rounded-lg border border-gray-700 bg-gray-950">
          {/* Status */}
          <div className="p-5">
            <div className="flex items-center gap-3">
              <span className={`w-2 h-2 rounded-full ${authEnabled ? 'bg-green-500' : 'bg-gray-500'}`} />
              <span className="text-sm text-gray-300">
                {authEnabled ? 'Authentication enabled' : 'Authentication disabled (open access)'}
              </span>
            </div>
            {!authEnabled && (
              <p className="mt-3 text-sm text-gray-500">
                Set <code className="px-1 py-0.5 bg-gray-800 rounded text-gray-400 text-xs">AUTH_ENABLED=true</code> in your <code className="px-1 py-0.5 bg-gray-800 rounded text-gray-400 text-xs">.env</code> or <code className="px-1 py-0.5 bg-gray-800 rounded text-gray-400 text-xs">docker-compose.yml</code> and restart the container to enable authentication.
              </p>
            )}
          </div>

          {!authEnabled && !authStatus?.has_users && (
            <>
              <div className="border-t border-gray-800" />
              <div className="p-5">
                {authStatus?.is_https ? (
                  <form onSubmit={handleEnableAuth} className="space-y-3 max-w-sm">
                    <p className="text-sm text-gray-500 mb-3">Create an admin account to enable authentication and protect your instance.</p>
                    <input
                      type="text"
                      placeholder="Username"
                      value={setupUser}
                      onChange={e => setSetupUser(e.target.value)}
                      disabled={setupSaving}
                      autoComplete="username"
                      className={`${INPUT_CLS} disabled:opacity-50`}
                    />
                    <input
                      type="password"
                      placeholder="Password (min 8 characters)"
                      value={setupPw}
                      onChange={e => setSetupPw(e.target.value)}
                      disabled={setupSaving}
                      autoComplete="new-password"
                      className={`${INPUT_CLS} disabled:opacity-50`}
                    />
                    <input
                      type="password"
                      placeholder="Confirm password"
                      value={setupConfirm}
                      onChange={e => setSetupConfirm(e.target.value)}
                      disabled={setupSaving}
                      autoComplete="new-password"
                      className={`${INPUT_CLS} disabled:opacity-50`}
                    />
                    <div className="flex items-center gap-3">
                      <button
                        type="submit"
                        disabled={setupSaving || !setupUser.trim() || setupPw.length < 8 || setupPw !== setupConfirm}
                        className="px-4 py-1.5 bg-teal-600 hover:bg-teal-500 text-white text-sm rounded disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                      >
                        {setupSaving ? 'Creating account...' : 'Enable Authentication'}
                      </button>
                      {setupStatus?.type === 'error' && (
                        <span className="text-sm text-red-400">{setupStatus.text}</span>
                      )}
                    </div>
                    <div className="mt-4 p-3 rounded bg-blue-500/10 border border-blue-500/30 text-sm text-blue-300">
                      <p className="font-medium text-blue-200">Using the browser extension?</p>
                      <p className="mt-1 text-blue-300/80">After enabling authentication:</p>
                      <ol className="mt-1.5 list-decimal list-inside space-y-1 text-blue-300/80">
                        <li>Update the extension to <strong className="text-blue-200">v1.1.0</strong> or later from the Chrome Web Store or Firefox Add-ons site</li>
                        <li>Go to <strong className="text-blue-200">Settings &rarr; API</strong> and create a token with client type <strong className="text-blue-200">Extension</strong></li>
                        <li>Paste the token into the extension popup</li>
                        <li>Ensure your controller URL in the extension uses <strong className="text-blue-200">HTTPS</strong></li>
                      </ol>
                      <p className="mt-2 text-blue-300/80">
                        For more details, see the{' '}
                        <a href="https://insightsplus.dev/docs/authentication" target="_blank" rel="noopener noreferrer" className="underline text-blue-200 hover:text-blue-100">Authentication docs</a>.
                      </p>
                    </div>
                  </form>
                ) : (
                  <div className="p-3 rounded bg-amber-500/10 border border-amber-500/30 text-sm text-amber-400">
                    Enabling authentication requires HTTPS. Please access the app through a reverse proxy with TLS enabled.
                  </div>
                )}
              </div>
            </>
          )}

          {authEnabled && me && (
            <>
              <div className="border-t border-gray-800" />
              <div className="p-5 space-y-3">
                <div className="flex items-center gap-2 text-sm">
                  <span className="text-gray-500">Signed in as:</span>
                  <span className="text-gray-200 font-medium">{me.username}</span>
                  <span className="px-1.5 py-0.5 text-xs rounded bg-gray-800 text-gray-400">{me.role || 'user'}</span>
                </div>
                <div className="flex items-center gap-3">
                  <button
                    onClick={() => { setShowPwChange(!showPwChange); setPwStatus(null) }}
                    className="text-sm text-teal-500 hover:text-teal-400 transition-colors"
                  >
                    Change password
                  </button>
                  {!showPwChange && pwStatus?.type === 'saved' && (
                    <span className="text-sm text-emerald-400">{pwStatus.text}</span>
                  )}
                </div>

                {showPwChange && (
                  <form onSubmit={handleChangePassword} className="mt-3 space-y-3 max-w-sm">
                    <input
                      type="password"
                      placeholder="Current password"
                      value={currentPw}
                      onChange={e => setCurrentPw(e.target.value)}
                      required
                      className={INPUT_CLS}
                    />
                    <input
                      type="password"
                      placeholder="New password (min 8 characters)"
                      value={newPw}
                      onChange={e => setNewPw(e.target.value)}
                      required
                      minLength={8}
                      className={INPUT_CLS}
                    />
                    <input
                      type="password"
                      placeholder="Confirm new password"
                      value={confirmPw}
                      onChange={e => setConfirmPw(e.target.value)}
                      required
                      className={INPUT_CLS}
                    />
                    <div className="flex items-center gap-3">
                      <button
                        type="submit"
                        disabled={pwSaving}
                        className="px-3 py-1.5 bg-teal-600 hover:bg-teal-500 text-white text-sm rounded disabled:opacity-50 transition-colors"
                      >
                        {pwSaving ? 'Saving...' : 'Update Password'}
                      </button>
                      <button
                        type="button"
                        onClick={handleCancelPwChange}
                        className="px-3 py-1.5 text-sm text-gray-400 hover:text-gray-200 transition-colors"
                      >
                        Cancel
                      </button>
                      {pwStatus?.type === 'error' && (
                        <span className="text-sm text-red-400">{pwStatus.text}</span>
                      )}
                    </div>
                  </form>
                )}
              </div>
            </>
          )}
        </div>
      </section>

      {authEnabled && (
        <section>
          <h2 className="text-base font-semibold text-gray-300 mb-3 uppercase tracking-wider">Session Duration</h2>
          <div className="rounded-lg border border-gray-700 bg-gray-950">
            <div className="p-5">
              <div className="flex items-center gap-3 max-w-sm">
                <select
                  value={sessionTtl}
                  onChange={e => { setSessionTtl(Number(e.target.value)); setTtlStatus(null) }}
                  className="px-3 py-1.5 bg-gray-900 border border-gray-700 rounded text-sm text-gray-200 focus:outline-none focus:border-teal-500"
                >
                  <option value={1}>1 hour</option>
                  <option value={4}>4 hours</option>
                  <option value={8}>8 hours</option>
                  <option value={24}>1 day</option>
                  <option value={72}>3 days</option>
                  <option value={168}>7 days</option>
                  <option value={720}>30 days</option>
                </select>
                <button
                  onClick={handleSaveSessionTtl}
                  disabled={ttlSaving || sessionTtl === authStatus?.session_ttl_hours}
                  className={`px-3 py-1.5 rounded text-sm font-medium transition-colors ${
                    sessionTtl !== authStatus?.session_ttl_hours
                      ? 'bg-teal-600 hover:bg-teal-500 text-white'
                      : 'bg-gray-800 text-gray-500 cursor-not-allowed'
                  }`}
                >
                  {ttlSaving ? 'Saving...' : 'Save'}
                </button>
              </div>
              <p className="mt-2 text-sm text-gray-500">How long sessions remain valid before requiring re-login. Changes apply to new sessions only.</p>
            </div>
            <div className="border-t border-gray-800" />
            <div className="px-5 py-3 flex items-center justify-between">
              <div>
                {ttlStatus === 'saved' && <span className="text-sm text-emerald-400">Session duration updated</span>}
                {ttlStatus === 'error' && <span className="text-sm text-red-400">Failed to save</span>}
              </div>
              <div /> {/* flex spacer — pushes status text left in justify-between layout */}
            </div>
          </div>
        </section>
      )}
    </div>
  )
}
