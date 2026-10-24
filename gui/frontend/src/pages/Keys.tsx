import { useState } from 'react'
import {
  ChangePassphrase, ContactText, ExportContact, ExportSecret, ImportKey, ImportKeyText,
  NewIdentity, OpenKeyringFolder, PickFile, Remove, SetDefault,
} from '../../wailsjs/go/main/App'
import { ClipboardSetText } from '../../wailsjs/runtime/runtime'
import { KeyInfo, errText } from '../api'
import { Menu, Modal, NewPassphrase, Notice, useApp } from '../components'
import * as I from '../icons'

type Dialog = { kind: 'new' } | { kind: 'paste' } | { kind: 'passphrase'; key: KeyInfo } | null

export default function KeysPage() {
  const { keyring, reloadKeyring, toast, run } = useApp()
  const [dialog, setDialog] = useState<Dialog>(null)

  const imported = (r: { message: string; warning: string } | undefined) => {
    if (!r) return
    toast(r.message, 'success')
    if (r.warning) toast(r.warning, 'warning')
    reloadKeyring()
  }
  const importFile = async () => {
    try {
      const p = await PickFile('Import a key (.pub, .key, .pem, .txt)')
      if (p) imported(await run(() => ImportKey(p, '')))
    } catch (e) {
      toast(errText(e), 'error')
    }
  }
  // act runs a key action; failures are toasted by run.
  const act = async <T,>(fn: () => Promise<T>, done?: (v: T) => void) => {
    const v = await run(fn)
    if (v !== undefined) done?.(v)
  }

  const menu = (k: KeyInfo) => {
    const own = k.kind === 'identity'
    const pub = k.kind !== 'legacy' && !k.error
    return [
      pub ? {
        label: 'Copy contact card', onClick: () => act(() => ContactText(k.name), (t) =>
          ClipboardSetText(t).then(() => toast('Contact card copied. Send it to people who will encrypt to you.', 'success'))),
      } : null,
      pub ? {
        label: 'Save contact card…', onClick: () => act(() => ExportContact(k.name), (p) => p && toast(`Saved ${p}`, 'success')),
      } : null,
      own && !k.error ? {
        label: 'Back up secret key…', onClick: () => act(() => ExportSecret(k.name), (p) => p && toast(`Saved ${p}`, 'success')),
      } : null,
      own && !k.default && !k.error ? {
        label: 'Make default', onClick: () => act(() => SetDefault(k.name).then(() => true), reloadKeyring),
      } : null,
      own && !k.error ? { label: k.locked ? 'Change passphrase…' : 'Add a passphrase…', onClick: () => setDialog({ kind: 'passphrase', key: k }) } : null,
      { label: own ? 'Delete key…' : 'Remove…', danger: true, onClick: () => act(() => Remove(k.kind, k.name), (gone) => gone && reloadKeyring()) },
    ].filter((x) => x !== null)
  }

  if (!keyring) return <div className="page"><div className="empty">Loading keyring…</div></div>

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1>Keys</h1>
          <p>Your keys decrypt files sent to you and sign files. Contacts are other people's public keys.</p>
        </div>
        <div className="actions">
          <button className="btn" onClick={() => setDialog({ kind: 'paste' })}><I.Clipboard /> Paste key</button>
          <button className="btn" onClick={importFile}><I.Upload /> Import…</button>
          <button className="btn primary" onClick={() => setDialog({ kind: 'new' })}><I.Plus /> New key</button>
        </div>
      </div>

      {keyring.identities.length === 0 && (
        <Notice kind="info">
          You don't have a key yet. Create one to receive encrypted files and sign — or just use passphrases on the
          Encrypt page, which needs no keys.
        </Notice>
      )}

      <KeySection title="Your keys" icon={<I.User className="icon faint" />} keys={keyring.identities} menu={menu}
        empty="No keys yet." />
      <KeySection title="Contacts" icon={<I.Users className="icon faint" />} keys={keyring.contacts} menu={menu}
        empty="No contacts. Import a contact card or paste an age1… or SSH public key." />
      {keyring.legacy.length > 0 && (
        <KeySection title="Old-format keys" icon={<I.Archive className="icon faint" />} keys={keyring.legacy} menu={menu}
          empty="" note="RSA keys from the older tools, used only to decrypt .enc files." />
      )}

      <div className="row small muted">
        <span className="ellipsis selectable" title={keyring.dir}>Stored in {keyring.dir}</span>
        <button className="btn ghost small" onClick={() => act(() => OpenKeyringFolder().then(() => true))}><I.Folder /> Open</button>
      </div>

      {dialog?.kind === 'new' && <NewKeyDialog onClose={() => setDialog(null)} first={keyring.identities.length === 0} />}
      {dialog?.kind === 'paste' && <PasteDialog onClose={() => setDialog(null)} onDone={imported} />}
      {dialog?.kind === 'passphrase' && <PassphraseDialog k={dialog.key} onClose={() => setDialog(null)} />}
    </div>
  )
}

function KeySection({ title, icon, keys, menu, empty, note }: {
  title: string
  icon: React.ReactNode
  keys: KeyInfo[]
  menu: (k: KeyInfo) => ({ label: string; onClick: () => void; danger?: boolean } | null)[]
  empty: string
  note?: string
}) {
  return (
    <div className="section">
      <div className="section-head">{icon}<h3>{title}</h3>{note && <span className="small faint">{note}</span>}</div>
      <div className="key-list">
        {keys.length === 0 && <div className="empty">{empty}</div>}
        {keys.map((k) => (
          <div className="key-row" key={k.name}>
            {k.kind === 'legacy' ? <I.Archive /> : k.kind === 'identity' ? <I.KeyIcon /> : <I.User />}
            <div className="grow" style={{ minWidth: 0 }}>
              <div className="title">
                <span className="ellipsis">{k.name}</span>
                {k.default && <span className="badge ok">Default</span>}
                {k.kind !== 'legacy' && !k.error && (k.postQuantum
                  ? <span className="badge pq"><I.Atom /> Post-quantum</span>
                  : <span className="badge">Classic</span>)}
                {k.kind === 'identity' && !k.error && (k.locked
                  ? <span className="badge"><I.Lock /> Passphrase</span>
                  : <span className="badge warn"><I.Unlock /> No passphrase</span>)}
                {k.kind !== 'legacy' && !k.error && !k.canSign && <span className="badge">Can't sign</span>}
                {k.error && <span className="badge bad">Unreadable</span>}
              </div>
              <div className="fp mono ellipsis selectable" title={k.recipient || k.error}>
                {k.error || k.fingerprint || (k.kind === 'legacy' ? 'RSA private key' : '')}
                {k.created && <span className="faint"> · added {k.created}</span>}
              </div>
            </div>
            <Menu items={menu(k)} />
          </div>
        ))}
      </div>
    </div>
  )
}

function NewKeyDialog({ onClose, first }: { onClose: () => void; first: boolean }) {
  const { run, toast, reloadKeyring, busy } = useApp()
  const [name, setName] = useState('')
  const [pass, setPass] = useState('')
  const [confirm, setConfirm] = useState('')
  const [classic, setClassic] = useState(false)
  const [makeDefault, setMakeDefault] = useState(first)
  const ok = name.trim() !== '' && (pass === '' || pass === confirm)

  const create = async () => {
    const k = await run(() => NewIdentity(name.trim(), pass, classic, makeDefault))
    if (!k) return
    toast(`Created your key “${k.name}”. Share its contact card so others can encrypt to you.`, 'success')
    reloadKeyring()
    onClose()
  }
  return (
    <Modal title="New key" onClose={onClose}>
      <label className="field">
        <span>Name</span>
        <input type="text" autoFocus value={name} placeholder="e.g. work, laptop, backups"
          onChange={(e) => setName(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter' && ok) create() }} />
      </label>
      <NewPassphrase value={pass} onChange={setPass} confirm={confirm} onConfirm={setConfirm} optional />
      {pass === '' && (
        <span className="hint">
          Without a passphrase anyone who can read your keyring can use this key. That's right for unattended jobs
          such as backups; for personal use, set one.
        </span>
      )}
      <label className="check">
        <input type="checkbox" checked={classic} onChange={(e) => setClassic(e.target.checked)} />
        Classic (X25519) key, for sharing with people using older age tools
      </label>
      {classic && <Notice>Classic keys are not safe against future quantum computers. Use post-quantum unless you need compatibility.</Notice>}
      <label className="check">
        <input type="checkbox" checked={makeDefault} disabled={first} onChange={(e) => setMakeDefault(e.target.checked)} />
        Make this my default key
      </label>
      <div className="modal-actions">
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn primary" disabled={!ok || busy} onClick={create}>Create key</button>
      </div>
    </Modal>
  )
}

function PasteDialog({ onClose, onDone }: { onClose: () => void; onDone: (r: { message: string; warning: string } | undefined) => void }) {
  const { run, busy } = useApp()
  const [text, setText] = useState('')
  const [name, setName] = useState('')
  const go = async () => {
    const r = await run(() => ImportKeyText(text, name))
    if (r) { onDone(r); onClose() }
  }
  return (
    <Modal title="Paste a key" onClose={onClose} wide>
      <label className="field">
        <span>Key</span>
        <textarea autoFocus value={text} onChange={(e) => setText(e.target.value)}
          placeholder="Paste a contact card, an age1… or SSH public key, or a secret key" />
      </label>
      <label className="field">
        <span>Name <span className="faint">(optional for contact cards)</span></span>
        <input type="text" value={name} onChange={(e) => setName(e.target.value)} />
      </label>
      <div className="modal-actions">
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn primary" disabled={!text.trim() || busy} onClick={go}>Import</button>
      </div>
    </Modal>
  )
}

function PassphraseDialog({ k, onClose }: { k: KeyInfo; onClose: () => void }) {
  const { run, toast, reloadKeyring, busy } = useApp()
  const [pass, setPass] = useState('')
  const [confirm, setConfirm] = useState('')
  const ok = pass === confirm
  const go = async () => {
    const r = await run(() => ChangePassphrase(k.name, pass).then(() => true))
    if (!r) return
    toast(pass ? 'Passphrase set.' : 'Passphrase removed. The key is now stored unprotected.', pass ? 'success' : 'warning')
    reloadKeyring()
    onClose()
  }
  return (
    <Modal title={`Passphrase for “${k.name}”`} onClose={onClose}>
      <NewPassphrase label="New passphrase" value={pass} onChange={setPass} confirm={confirm} onConfirm={setConfirm} optional />
      {pass === '' && k.locked && <Notice>Leaving this empty removes the passphrase, so the key can be used without asking.</Notice>}
      <div className="modal-actions">
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn primary" disabled={!ok || busy || (pass === '' && !k.locked)} onClick={go}>
          {pass === '' ? 'Remove passphrase' : 'Save'}
        </button>
      </div>
    </Modal>
  )
}
