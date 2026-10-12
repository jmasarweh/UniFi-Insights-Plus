import SettingsPihole from './SettingsPihole'
import SettingsTechnitium from './SettingsTechnitium'

export default function SettingsIntegrations() {
  return (
    <div className="space-y-10">
      <SettingsPihole />
      <SettingsTechnitium />
    </div>
  )
}
