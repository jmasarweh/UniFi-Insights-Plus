/**
 * Component tests for the cleanup-time input in SettingsDataBackups.
 * Covers: initial render matches saved value, dirty detection, save payload,
 * and footer reflects the saved (not pending) time. Minute-precision paths
 * (e.g. 23:17) are explicitly asserted — the ability to pick non-hour-boundary
 * times is the whole reason this input is a time picker, not an hour select.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react'

const mockUpdateRetentionConfig = vi.fn(() => Promise.resolve({ success: true }))

vi.mock('../api', () => ({
  fetchRetentionConfig: vi.fn(() => Promise.resolve({
    retention_days: 60, dns_retention_days: 10, retention_time: '15:30',
  })),
  updateRetentionConfig: (...args) => mockUpdateRetentionConfig(...args),
  runRetentionCleanup: vi.fn(() => Promise.resolve({ success: true, status: 'running' })),
  fetchRetentionCleanupStatus: vi.fn(() => Promise.resolve({ status: 'idle' })),
  exportConfig: vi.fn(() => Promise.resolve({})),
  importConfig: vi.fn(() => Promise.resolve({})),
  testMigrationConnection: vi.fn(() => Promise.resolve({ success: true })),
  startMigration: vi.fn(() => Promise.resolve({ success: true })),
  getMigrationStatus: vi.fn(() => Promise.resolve({ status: 'idle', is_external: false })),
  patchMigrationCompose: vi.fn(() => Promise.resolve({})),
  fetchLogCountsByType: vi.fn(() => Promise.resolve({ firewall: 0, dns: 0, wifi: 0, system: 0 })),
  purgeLogsByType: vi.fn(() => Promise.resolve({})),
  fetchPurgeStatus: vi.fn(() => Promise.resolve({})),
  fetchUiSettings: vi.fn(() => Promise.resolve({
    wifi_processing_enabled: true, system_processing_enabled: true,
  })),
  updateUiSettings: vi.fn(() => Promise.resolve({})),
}))

vi.mock('../components/CopyButton', () => ({ default: (props) => <button>{props.text}</button> }))
vi.mock('../components/InfoTooltip', () => ({ default: () => <span /> }))
vi.mock('../components/SyslogToggle', () => ({ default: () => <div /> }))

import SettingsDataBackups from '../components/SettingsDataBackups'

beforeEach(() => {
  vi.clearAllMocks()
  mockUpdateRetentionConfig.mockResolvedValue({ success: true })
})

describe('retention time input', () => {
  it('shows the saved time after initial load', async () => {
    render(<SettingsDataBackups totalLogs={0} storage={null} />)
    const input = await screen.findByLabelText(/cleanup time/i)
    expect(input.value).toBe('15:30')
  })

  it('footer reflects the saved time, not the pending one', async () => {
    render(<SettingsDataBackups totalLogs={0} storage={null} />)
    await screen.findByLabelText(/cleanup time/i)
    expect(screen.getByText(/Cleanup runs daily at 15:30/)).toBeInTheDocument()

    // Change the input without saving — footer must NOT update yet.
    fireEvent.change(screen.getByLabelText(/cleanup time/i), { target: { value: '07:45' } })
    expect(screen.getByText(/Cleanup runs daily at 15:30/)).toBeInTheDocument()
    expect(screen.queryByText(/Cleanup runs daily at 07:45/)).not.toBeInTheDocument()
  })

  it('enables Save and sends minute-precision time in the payload', async () => {
    render(<SettingsDataBackups totalLogs={0} storage={null} />)
    await screen.findByLabelText(/cleanup time/i)

    const timeInput = screen.getByLabelText(/cleanup time/i)
    const card = timeInput.closest('.rounded-lg')
    const saveBtn = within(card).getByRole('button', { name: /^Save$/ })

    expect(saveBtn).toBeDisabled()

    // 23:17 — specifically the case the user called out as needing to work.
    fireEvent.change(timeInput, { target: { value: '23:17' } })
    expect(saveBtn).not.toBeDisabled()

    fireEvent.click(saveBtn)
    await waitFor(() => expect(mockUpdateRetentionConfig).toHaveBeenCalled())
    const payload = mockUpdateRetentionConfig.mock.calls[0][0]
    expect(payload).toMatchObject({
      retention_days: 60,
      dns_retention_days: 10,
      retention_time: '23:17',
    })
  })
})
