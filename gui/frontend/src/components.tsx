import React, { createContext, useContext, useEffect, useRef, useState } from 'react'
import { GeneratePassphrase, PickDirectory, PickFiles, RevealInFolder } from '../wailsjs/go/main/App'
import { ClipboardSetText } from '../wailsjs/runtime/runtime'
import { FileInfo, KeyringState, OpResult, baseName, errText, fmtSize, strength } from './api'
import * as I from './icons'
import { InspectModal } from './Inspect'

// --- app context -----------------------------------------------------------

export type ToastKind = 'info' | 'success' | 'warning' | 'error'

export interface AppCtx {
  keyring: KeyringState | null
  reloadKeyring: () => Promise<void>
  toast: (msg: string, kind?: ToastKind) => void
  busy: boolean
  // run executes one backend operation, showing progress; it resolves to
  // undefined if the call failed (the error has been shown).
  run: <T>(fn: () => Promise<T>) => Promise<T | undefined>
}

export const Ctx = createContext<AppCtx>(null as unknown as AppCtx)
export const useApp = () => useContext(Ctx)

// --- files -----------------------------------------------------------------

export function fileDetail(f: FileInfo): string {
  const parts = [fmtSize(f.size)]
  if (f.kind !== 'plain') parts.push(f.kindLabel)
  if (f.kind === 'age' && f.recipients?.length) parts.push('for ' + f.recipients.join(', '))
  if (f.kind === 'signature' && f.signer) {
    parts.push('by ' + (f.signer.known ? f.signer.name : f.signer.fingerprint))
  }
  return parts.join(' · ')
}

export function FilePicker({ files, onAdd, onRemove, onClear, hint, pickTitle }: {
  files: FileInfo[]
  onAdd: (paths: string[]) => void
  onRemove: (path: string) => void
  onClear: () => void
  hint: string
  pickTitle: string
}) {
  const { toast } = useApp()
  const [inspecting, setInspecting] = useState('')
  const pick = async () => {
    try {
      const p = await PickFiles(pickTitle)
      if (p?.length) onAdd(p)
    } catch (e) {
      toast(errText(e), 'error')
    }
  }
  if (!files.length) {
    return (
      <div className="dropzone">
        <I.Upload />
        <div>{hint}</div>
        <button className="btn" onClick={pick}><I.Plus /> Choose files…</button>
      </div>
    )
  }
  const total = files.reduce((n, f) => n + (f.size || 0), 0)
  return (
    <div className="file-list">
      <div className="file-rows">
      {files.map((f) => (
        <div className="file-row" key={f.path}>
          {f.kind === 'plain' ? <I.File /> : f.kind === 'signature' ? <I.Pen /> : <I.FileLock />}
          <div className="grow">
            <div className="row" style={{ gap: 7 }}>
              <span className="name ellipsis" title={f.path}>{f.name}</span>
              {f.postQuantum && <span className="badge pq"><I.Atom /> Post-quantum</span>}
              {f.kind === 'legacy' && <span className="badge warn">Legacy</span>}
            </div>
            {f.error ? <div className="error">{f.error}</div> : <div className="detail ellipsis">{fileDetail(f)}</div>}
          </div>
          {!f.error && <button className="btn ghost icon-btn" title="Inspect" onClick={() => setInspecting(f.path)}><I.Info /></button>}
          <button className="btn ghost icon-btn" title="Remove from list" onClick={() => onRemove(f.path)}><I.X /></button>
        </div>
      ))}
      </div>
      <div className="file-list-footer">
        <span>{files.length} file{files.length === 1 ? '' : 's'} · {fmtSize(total)}</span>
        <span className="grow" />
        <button className="btn ghost small" onClick={pick}><I.Plus /> Add</button>
        <button className="btn ghost small" onClick={onClear}>Clear</button>
      </div>
      {inspecting && <InspectModal path={inspecting} onClose={() => setInspecting('')} />}
    </div>
  )
}

export function OutputDir({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const { toast } = useApp()
  const pick = async () => {
    try {
      const d = await PickDirectory('Output folder')
      if (d) onChange(d)
    } catch (e) {
      toast(errText(e), 'error')
    }
  }
  return (
    <label className="field">
      <span>Save to</span>
      <div className="row" style={{ flexWrap: 'nowrap' }}>
        <div className="grow ellipsis" style={{ color: value ? 'var(--text-0)' : 'var(--text-2)' }} title={value}>
          {value || 'Next to each original file'}
        </div>
        <button className="btn small" onClick={pick}><I.Folder /> Choose…</button>
        {value && <button className="btn ghost small" onClick={() => onChange('')}>Reset</button>}
      </div>
    </label>
  )
}

// --- results ---------------------------------------------------------------

export function Results({ results, onDismiss }: { results: OpResult[]; onDismiss: () => void }) {
  const { toast } = useApp()
  if (!results.length) return null
  const ok = results.filter((r) => r.ok).length
  const failed = results.filter((r) => !r.ok && !r.skipped).length
  const reveal = (p: string) => RevealInFolder(p).catch((e) => toast(errText(e), 'error'))
  return (
    <div className="card">
      <div className="card-title">
        <h2>Results</h2>
        <span className="muted small">
          {ok} done{failed ? `, ${failed} failed` : ''}{results.length - ok - failed ? `, ${results.length - ok - failed} skipped` : ''}
        </span>
        <div className="actions"><button className="btn ghost small" onClick={onDismiss}>Dismiss</button></div>
      </div>
      <div className="file-list">
        {results.map((r, i) => (
          <div key={i} className={'result ' + (r.ok ? 'ok' : r.skipped ? 'skip' : 'fail')}>
            {r.ok ? <I.CheckCircle /> : r.skipped ? <I.MinusCircle /> : <I.XCircle />}
            <div className="body">
              <div className="row" style={{ gap: 7 }}>
                <span className="ellipsis" title={r.input}>{baseName(r.input)}</span>
                {r.output && r.ok && <span className="faint ellipsis small" title={r.output}>→ {baseName(r.output)}</span>}
                {r.format && <span className="badge">{r.format}</span>}
                {r.signed && r.signer && (
                  <span className={'badge ' + (r.signer.known ? 'ok' : 'warn')}>
                    <I.Pen /> {r.signer.known ? r.signer.name : 'Unknown signer'}
                  </span>
                )}
              </div>
              {r.signed && r.signer && !r.signer.known && (
                <span className="small faint mono selectable">{r.signer.fingerprint}</span>
              )}
              {r.error && <span className={r.skipped ? 'faint small' : 'err'}>{r.error}</span>}
              {r.warnings?.map((w, j) => <span key={j} className="warn">{w}</span>)}
            </div>
            {r.ok && r.output && (
              <button className="btn ghost small" onClick={() => reveal(r.output)}><I.Folder /> Show</button>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

// --- passphrase field ------------------------------------------------------

export function PasswordInput({ value, onChange, placeholder, autoFocus, onEnter }: {
  value: string
  onChange: (v: string) => void
  placeholder?: string
  autoFocus?: boolean
  onEnter?: () => void
}) {
  const [show, setShow] = useState(false)
  return (
    <div className="password-row">
      <input type={show ? 'text' : 'password'} value={value} placeholder={placeholder} autoFocus={autoFocus}
        spellCheck={false} autoComplete="off" onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => { if (e.key === 'Enter' && onEnter) onEnter() }} />
      <button className="btn icon-btn" type="button" title={show ? 'Hide' : 'Show'} onClick={() => setShow(!show)}>
        {show ? <I.EyeOff /> : <I.Eye />}
      </button>
    </div>
  )
}

// NewPassphrase is a passphrase plus confirmation, with a generator and a
// strength meter. It reports "" while the two entries differ.
export function NewPassphrase({ value, onChange, confirm, onConfirm, label = 'Passphrase', optional }: {
  value: string
  onChange: (v: string) => void
  confirm: string
  onConfirm: (v: string) => void
  label?: string
  optional?: boolean
}) {
  const { toast } = useApp()
  const s = strength(value)
  const colours = ['var(--bg-3)', 'var(--danger)', 'var(--warning)', 'var(--accent)', 'var(--success)']
  const generate = async () => {
    const p = await GeneratePassphrase()
    onChange(p)
    onConfirm(p)
    ClipboardSetText(p).then(() => toast('Generated passphrase copied to the clipboard. Store it somewhere safe.', 'info'))
  }
  const mismatch = confirm !== '' && confirm !== value
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <label className="field">
        <span>{label}{optional && <span className="faint"> (optional)</span>}</span>
        <div className="row" style={{ flexWrap: 'nowrap', gap: 6 }}>
          <div className="grow"><PasswordInput value={value} onChange={onChange} /></div>
          <button className="btn" type="button" onClick={generate} title="Generate a random passphrase"><I.Dice /> Generate</button>
        </div>
      </label>
      {value && (
        <div className="row" style={{ flexWrap: 'nowrap' }}>
          <div className="meter grow"><div style={{ width: `${s.score * 25}%`, background: colours[s.score] }} /></div>
          <span className="small muted" style={{ width: 44 }}>{s.label}</span>
        </div>
      )}
      {value && (
        <label className="field">
          <span>Confirm</span>
          <PasswordInput value={confirm} onChange={onConfirm} />
          {mismatch && <span className="small" style={{ color: 'var(--danger)' }}>The passphrases don't match.</span>}
        </label>
      )}
    </div>
  )
}

// --- modal and menu --------------------------------------------------------

export function Modal({ title, children, onClose, wide }: {
  title: string
  children: React.ReactNode
  onClose: () => void
  wide?: boolean
}) {
  useEffect(() => {
    const k = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', k)
    return () => window.removeEventListener('keydown', k)
  }, [onClose])
  return (
    <div className="overlay" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}>
      <div className={'modal' + (wide ? ' wide' : '')} role="dialog" aria-label={title}>
        <h2>{title}</h2>
        {children}
      </div>
    </div>
  )
}

// Menu is fixed to the window so lists that clip or scroll cannot hide it;
// it opens upwards when there is no room below, and closes on scroll.
export function Menu({ items }: { items: ({ label: string; onClick: () => void; danger?: boolean } | null)[] }) {
  const [pos, setPos] = useState<React.CSSProperties | null>(null)
  const ref = useRef<HTMLDivElement>(null)
  const open = pos !== null
  useEffect(() => {
    if (!open) return
    const close = (e: Event) => {
      if (e.type !== 'resize' && ref.current?.contains(e.target as Node)) return
      setPos(null)
    }
    window.addEventListener('mousedown', close)
    window.addEventListener('scroll', close, true)
    window.addEventListener('resize', close)
    return () => {
      window.removeEventListener('mousedown', close)
      window.removeEventListener('scroll', close, true)
      window.removeEventListener('resize', close)
    }
  }, [open])
  const toggle = (e: React.MouseEvent<HTMLButtonElement>) => {
    if (open) return setPos(null)
    const r = e.currentTarget.getBoundingClientRect()
    const right = window.innerWidth - r.right
    setPos(r.bottom + 4 + menuHeight(items) > window.innerHeight - 8
      ? { right, bottom: window.innerHeight - r.top + 4 }
      : { right, top: r.bottom + 4 })
  }
  return (
    <div className="menu-wrap" ref={ref}>
      <button className="btn ghost icon-btn" title="More actions" onClick={toggle}><I.More /></button>
      {pos && (
        <div className="menu" style={pos}>
          {items.map((it, i) => it === null ? <hr key={i} /> : (
            <button key={i} className={it.danger ? 'danger' : ''} onClick={() => { setPos(null); it.onClick() }}>{it.label}</button>
          ))}
        </div>
      )}
    </div>
  )
}

// menuHeight estimates a menu's height from its items (see .menu styles).
function menuHeight(items: unknown[]): number {
  return 10 + items.reduce<number>((h, it) => h + (it === null ? 9 : 30), 0)
}

export function Notice({ kind = 'warning', children }: { kind?: 'warning' | 'info' | 'error'; children: React.ReactNode }) {
  return (
    <div className={'notice' + (kind === 'warning' ? '' : ' ' + kind)}>
      {kind === 'info' ? <I.Info /> : <I.Alert />}
      <div>{children}</div>
    </div>
  )
}
