import { useState, useRef, useEffect, useCallback, useId } from 'react'
import { createPortal } from 'react-dom'

export default function InfoTooltip({ children }) {
  const [open, setOpen] = useState(false)
  const [style, setStyle] = useState(null)
  const btnRef = useRef(null)
  const popupRef = useRef(null)
  const popupId = useId()

  const close = useCallback(() => setOpen(false), [])

  // Compute popup position, clamped to viewport (horizontal + vertical)
  const reposition = useCallback(() => {
    const btn = btnRef.current
    const popup = popupRef.current
    if (!btn || !popup) return
    const rect = btn.getBoundingClientRect()
    const pw = popup.offsetWidth
    const ph = popup.offsetHeight
    const pad = 8
    const gap = 6
    // Horizontal: center on button, clamp to viewport
    let left = rect.left + rect.width / 2 - pw / 2
    if (left < pad) left = pad
    if (left + pw > window.innerWidth - pad) left = window.innerWidth - pad - pw
    // Vertical: prefer below, flip above if it would overflow
    let top = rect.bottom + gap
    if (top + ph > window.innerHeight - pad) top = rect.top - ph - gap
    if (top < pad) top = pad
    setStyle({ position: 'fixed', left, top })
  }, [])

  const toggle = () => {
    if (open) { close(); return }
    setOpen(true)
  }

  // Position after open and on resize/scroll
  useEffect(() => {
    if (!open) return
    // Wait one frame for popup to mount and measure
    const raf = requestAnimationFrame(reposition)
    window.addEventListener('resize', reposition)
    window.addEventListener('scroll', close, true)
    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('resize', reposition)
      window.removeEventListener('scroll', close, true)
    }
  }, [open, reposition, close])

  useEffect(() => {
    if (!open) return
    const handler = (e) => {
      if (btnRef.current?.contains(e.target)) return
      if (popupRef.current?.contains(e.target)) return
      close()
    }
    const esc = (e) => { if (e.key === 'Escape') close() }
    document.addEventListener('pointerdown', handler)
    document.addEventListener('keydown', esc)
    return () => {
      document.removeEventListener('pointerdown', handler)
      document.removeEventListener('keydown', esc)
    }
  }, [open, close])

  return (
    <>
      <button
        ref={btnRef}
        type="button"
        onClick={toggle}
        className="info-tooltip-btn"
        aria-label="Show help"
        aria-expanded={open}
        aria-controls={open ? popupId : undefined}
      >
        <svg className="w-3.5 h-3.5" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
          <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a.75.75 0 000 1.5h.253a.25.25 0 01.244.304l-.459 2.066A1.75 1.75 0 0010.747 15H11a.75.75 0 000-1.5h-.253a.25.25 0 01-.244-.304l.459-2.066A1.75 1.75 0 009.253 9H9z" clipRule="evenodd" />
        </svg>
      </button>
      {open && createPortal(
        <div
          ref={popupRef}
          id={popupId}
          className="info-tooltip-popup"
          role="tooltip"
          style={style || { position: 'fixed', left: -9999, top: -9999 }}
        >
          {children}
        </div>,
        document.body
      )}
    </>
  )
}
