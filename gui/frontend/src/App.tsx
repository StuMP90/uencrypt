import { useCallback, useEffect, useRef, useState } from 'react'
import { AnswerPrompt, Cancel, InitialFiles, Inspect, Keyring } from '../wailsjs/go/main/App'
import { FileInfo, KeyringState, Progress, Prompt, baseName, errText, fmtSize, useEvent } from './api'
import { AppCtx, Ctx, Modal, PasswordInput, ToastKind } from './components'
import * as I from './icons'
import EncryptPage from './pages/Encrypt'
import DecryptPage from './pages/Decrypt'
import SignPage from './pages/Sign'
import KeysPage from './pages/Keys'
import AboutPage from './pages/About'
import logo from './assets/logo.png'

export type PageId = 'encrypt' | 'decrypt' | 'sign' | 'keys' | 'about'
type FilePage = 'encrypt' | 'decrypt' | 'sign'

const nav: { id: PageId; label: string; icon: () => React.JSX.Element }[] = [
  { id: 'encrypt', label: 'Encrypt', icon: () => <I.Lock /> },
  { id: 'decrypt', label: 'Decrypt', icon: () => <I.Unlock /> },
  { id: 'sign', label: 'Sign & Verify', icon: () => <I.Pen /> },
  { id: 'keys', label: 'Keys', icon: () => <I.KeyIcon /> },
]

// A plain file with an error could not be read at all (missing, a folder).
const unusable = (f: FileInfo) => f.kind === 'plain' && !!f.error

interface Toast { id: number; msg: string; kind: ToastKind }

export default function App() {
  const [page, setPage] = useState<PageId>('encrypt')
  const [files, setFiles] = useState<Record<FilePage, FileInfo[]>>({ encrypt: [], decrypt: [], sign: [] })
  const [verifyFile, setVerifyFile] = useState<FileInfo | null>(null)
  const [keyring, setKeyring] = useState<KeyringState | null>(null)
  const [toasts, setToasts] = useState<Toast[]>([])
  const [prompts, setPrompts] = useState<Prompt[]>([])
  const [busy, setBusy] = useState(false)
  const [progress, setProgress] = useState<Progress | null>(null)
  const [dragging, setDragging] = useState(false)
  const toastId = useRef(0)

  const toast = useCallback((msg: string, kind: ToastKind = 'info') => {
    const id = ++toastId.current
    setToasts((t) => [...t, { id, msg, kind }])
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), kind === 'error' ? 9000 : 5000)
  }, [])

  const reloadKeyring = useCallback(async () => {
    try {
      setKeyring(await Keyring())
    } catch (e) {
      toast('Could not open the keyring: ' + errText(e), 'error')
    }
  }, [toast])

  const run = useCallback(async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
    setBusy(true)
    setProgress(null)
    try {
      return await fn()
    } catch (e) {
      toast(errText(e), 'error')
      return undefined
    } finally {
      setBusy(false)
      setProgress(null)
    }
  }, [toast])

  // addFiles inspects paths and adds them to a page's list.
  const addFiles = useCallback(async (target: FilePage, paths: string[]) => {
    try {
      const info = await Inspect(paths)
      const bad = info.filter(unusable)
      bad.forEach((f) => toast(`${baseName(f.path)}: ${f.error}`, 'error'))
      const good = info.filter((f) => !bad.includes(f))
      setFiles((all) => {
        const have = new Set(all[target].map((f) => f.path))
        return { ...all, [target]: [...all[target], ...good.filter((f) => !have.has(f.path))] }
      })
    } catch (e) {
      toast(errText(e), 'error')
    }
  }, [toast])

  // routeFiles sends dropped or opened files to the page that fits them:
  // a signature goes to Verify, encrypted files to Decrypt, anything else to
  // Encrypt.
  const routeFiles = useCallback(async (paths: string[]) => {
    if (!paths.length) return
    try {
      const info = await Inspect(paths)
      const usable = info.filter((f) => !unusable(f))
      info.filter(unusable).forEach((f) => toast(`${baseName(f.path)}: ${f.error}`, 'error'))
      if (!usable.length) return
      if (usable.length === 1 && usable[0].kind === 'signature') {
        setVerifyFile(usable[0])
        setPage('sign')
        return
      }
      const enc = usable.filter((f) => f.kind === 'age' || f.kind === 'legacy')
      const target: FilePage = enc.length === usable.length ? 'decrypt' : 'encrypt'
      // On a page that takes files, a drop adds to that page unless every
      // file is encrypted (which always means Decrypt).
      const dest: FilePage = target === 'decrypt' ? 'decrypt'
        : page === 'sign' ? 'sign' : 'encrypt'
      setFiles((all) => {
        const have = new Set(all[dest].map((f) => f.path))
        return { ...all, [dest]: [...all[dest], ...usable.filter((f) => !have.has(f.path))] }
      })
      setPage(dest)
    } catch (e) {
      toast(errText(e), 'error')
    }
  }, [page, toast])

  useEffect(() => {
    reloadKeyring()
    InitialFiles().then((p) => { if (p?.length) routeFiles(p) })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEvent<string[]>('files', (paths) => { setDragging(false); routeFiles(paths) })
  useEvent<Prompt>('prompt', (p) => setPrompts((q) => [...q, p]))
  useEvent<string>('prompt-close', (id) => setPrompts((q) => q.filter((p) => p.id !== id)))
  useEvent<Progress>('progress', setProgress)

  // The window-level drag events only drive the highlight; the drop itself
  // arrives from Go as a "files" event with real paths.
  useEffect(() => {
    let depth = 0
    const enter = (e: DragEvent) => { if (e.dataTransfer?.types.includes('Files')) { depth++; setDragging(true) } }
    const leave = () => { depth = Math.max(0, depth - 1); if (!depth) setDragging(false) }
    const drop = () => { depth = 0; setDragging(false) }
    const over = (e: DragEvent) => e.preventDefault()
    window.addEventListener('dragenter', enter)
    window.addEventListener('dragleave', leave)
    window.addEventListener('drop', drop)
    window.addEventListener('dragover', over)
    return () => {
      window.removeEventListener('dragenter', enter)
      window.removeEventListener('dragleave', leave)
      window.removeEventListener('drop', drop)
      window.removeEventListener('dragover', over)
    }
  }, [])

  const answer = (p: Prompt, value: string, cancelled: boolean) => {
    AnswerPrompt(p.id, value, cancelled)
    setPrompts((q) => q.filter((x) => x.id !== p.id))
  }

  const ctx: AppCtx = { keyring, reloadKeyring, toast, busy, run }
  const fileProps = (p: FilePage) => ({
    files: files[p],
    onAdd: (paths: string[]) => addFiles(p, paths),
    onRemove: (path: string) => setFiles((all) => ({ ...all, [p]: all[p].filter((f) => f.path !== path) })),
    onClear: () => setFiles((all) => ({ ...all, [p]: [] })),
  })

  return (
    <Ctx.Provider value={ctx}>
      <div className={'app' + (dragging ? ' dragging' : '')}>
        <aside className="sidebar">
          <div className="brand"><img src={logo} alt="" /> uEncrypt</div>
          {nav.map((n) => (
            <button key={n.id} className={'nav-item' + (page === n.id ? ' active' : '')} onClick={() => setPage(n.id)}>
              {n.icon()} {n.label}
              {(n.id === 'encrypt' || n.id === 'decrypt' || n.id === 'sign') && files[n.id].length > 0 &&
                <span className="count">{files[n.id].length}</span>}
            </button>
          ))}
          <div className="spacer" />
          <button className={'nav-item' + (page === 'about' ? ' active' : '')} onClick={() => setPage('about')}>
            <I.Info /> About
          </button>
        </aside>

        <main className="main">
          {page === 'encrypt' && <EncryptPage {...fileProps('encrypt')} />}
          {page === 'decrypt' && <DecryptPage {...fileProps('decrypt')} />}
          {page === 'sign' && <SignPage {...fileProps('sign')} verifyFile={verifyFile} setVerifyFile={setVerifyFile} />}
          {page === 'keys' && <KeysPage />}
          {page === 'about' && <AboutPage />}

          {busy && (
            <div className="statusbar">
              <span className="small muted ellipsis" style={{ maxWidth: '45%' }}>
                {progress?.file ? baseName(progress.file) : 'Working…'}
                {progress && progress.total > 0 && ` · ${fmtSize(progress.done)} of ${fmtSize(progress.total)}`}
              </span>
              <div className={'progress' + (progress && progress.total > 0 ? '' : ' indeterminate')}>
                <div style={progress && progress.total > 0 ? { width: `${(100 * progress.done) / progress.total}%` } : undefined} />
              </div>
              <button className="btn small" onClick={() => Cancel()}>Cancel</button>
            </div>
          )}
        </main>
      </div>

      {prompts.length > 0 && <PromptModal key={prompts[0].id} prompt={prompts[0]} onAnswer={answer} />}

      <div className="toasts">
        {toasts.map((t) => <div key={t.id} className={'toast ' + t.kind}>{t.msg}</div>)}
      </div>
    </Ctx.Provider>
  )
}

function PromptModal({ prompt, onAnswer }: { prompt: Prompt; onAnswer: (p: Prompt, v: string, cancelled: boolean) => void }) {
  const [value, setValue] = useState('')
  const cancel = () => onAnswer(prompt, '', true)
  const ok = () => onAnswer(prompt, value, false)
  return (
    <Modal title={prompt.title} onClose={cancel}>
      <p>{prompt.message}</p>
      {prompt.kind === 'passphrase' && (
        <PasswordInput value={value} onChange={setValue} autoFocus onEnter={ok} />
      )}
      {prompt.error && <div className="error-text">{prompt.error}</div>}
      <div className="modal-actions">
        <button className="btn" onClick={cancel}>Cancel</button>
        <button className={'btn ' + (/remove|replace|delete|anyway/i.test(prompt.confirm) ? 'danger' : 'primary')}
          autoFocus={prompt.kind === 'confirm'} onClick={ok}>{prompt.confirm || 'OK'}</button>
      </div>
    </Modal>
  )
}
