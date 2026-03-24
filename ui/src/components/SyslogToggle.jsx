/** Toggle switch matching UniFi style: 32×16 track, 14×14 knob. */
export default function SyslogToggle({ checked, disabled, onChange, title }) {
  return (
    <button
      type="button"
      onClick={() => onChange?.(!checked)}
      disabled={disabled}
      role="switch"
      aria-checked={checked}
      aria-label={title || 'Toggle syslog'}
      title={title}
    >
      <div
        className={`relative w-8 h-4 rounded-full transition-colors duration-200 ${
          disabled
            ? (checked ? 'bg-teal-800' : 'bg-[#282b2f]')
            : (checked ? 'bg-teal-500' : 'bg-[#42474d]')
        } ${disabled ? 'cursor-not-allowed' : 'cursor-pointer'}`}
      >
        <div
          className="absolute top-[1px] w-[14px] h-[14px] rounded-full bg-white"
          style={{
            left: checked ? '17px' : '1px',
            transition: 'left .25s cubic-bezier(.8, 0, .6, 1.4)',
            boxShadow: '0 4px 12px 0 rgba(0,0,0,.4), 0 0 1px 0 hsla(214,8%,98%,.08)',
          }}
        />
      </div>
    </button>
  )
}
