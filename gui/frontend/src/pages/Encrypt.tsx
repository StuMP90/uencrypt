import { useEffect, useMemo, useState } from 'react'
import { Encrypt } from '../../wailsjs/go/main/App'
import { main } from '../../wailsjs/go/models'
import { FileInfo, KeyInfo, OpResult } from '../api'
import { FilePicker, NewPassphrase, Notice, OutputDir, Results, useApp } from '../components'
import * as I from '../icons'

interface Props {
  files: FileInfo[]
  onAdd: (p: string[]) => void
  onRemove: (p: string) => void
  onClear: () => void
}

export default function EncryptPage(props: Props) {
  const { keyring, busy, run, toast } = useApp()
  const [mode, setMode] = useState<'keys' | 'password'>('keys')
  const [selected, setSelected] = useState<string[] | null>(null)
  const [extra, setExtra] = useState('')
  const [pass, setPass] = useState('')
  const [pass2, setPass2] = useState('')
  const [sign, setSign] = useState(false)
  const [signAs, setSignAs] = useState('')
  const [armor, setArmor] = useState(false)
  const [overwrite, setOverwrite] = useState(false)
  const [outputDir, setOutputDir] = useState('')
  const [results, setResults] = useState<OpResult[]>([])

  const candidates: KeyInfo[] = useMemo(
    () => [...(keyring?.identities ?? []), ...(keyring?.contacts ?? [])].filter((k) => !k.error),
    [keyring])
  const signers = (keyring?.identities ?? []).filter((k) => k.canSign && !k.error)

  // Preselect the default identity once the keyring has loaded.
  useEffect(() => {
    if (selected === null && keyring) setSelected(keyring.default ? [keyring.default] : [])
  }, [keyring, selected])
  useEffect(() => {
    if (!signAs && signers.length) setSignAs(signers.find((k) => k.default)?.name ?? signers[0].name)
  }, [signers, signAs])

  const chosen = selected ?? []
  const extraKeys = splitKeys(extra)
  const recipients = [...chosen, ...extraKeys]
  const chosenInfo = candidates.filter((k) => chosen.includes(k.name))
  const extraPQ = extraKeys.map((k) => k.startsWith('age1pq1'))
  const pqFlags = [...chosenInfo.map((k) => k.postQuantum), ...extraPQ]
  const mixed = pqFlags.includes(true) && pqFlags.includes(false)
  const allPQ = pqFlags.length > 0 && !pqFlags.includes(false)
  const badExtra = extraKeys.filter((k) => !/^age1[0-9a-z]+$/.test(k) && !/^(ssh-ed25519|ssh-rsa) [A-Za-z0-9+/=]+$/.test(k))
  const plainFiles = props.files.filter((f) => !f.error)

  const ready = plainFiles.length > 0 && !busy && (mode === 'keys'
    ? recipients.length > 0 && !mixed && badExtra.length === 0
    : pass !== '' && pass === pass2) && (!sign || signAs !== '')

  const toggle = (name: string) =>
    setSelected(chosen.includes(name) ? chosen.filter((n) => n !== name) : [...chosen, name])

  const go = async () => {
    const req = main.EncryptRequest.createFrom({
      files: plainFiles.map((f) => f.path), outputDir, mode, recipients: mode === 'keys' ? recipients : [],
      passphrase: mode === 'password' ? pass : '', sign, signAs: sign ? signAs : '', armor, overwrite,
    })
    const r = await run(() => Encrypt(req))
    if (r) {
      setResults(r)
      const ok = r.filter((x) => x.ok).length
      if (ok) toast(`Encrypted ${ok} file${ok === 1 ? '' : 's'}.`, 'success')
      if (r.every((x) => x.ok)) props.onClear()
    }
  }

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1>Encrypt</h1>
          <p>Protect files for yourself or for other people, with a key or a passphrase.</p>
        </div>
      </div>

      <FilePicker {...props} hint="Drop files here to encrypt them" pickTitle="Choose files to encrypt" />

      {props.files.some((f) => f.kind === 'age' || f.kind === 'legacy') && (
        <Notice>Some of these files are already encrypted. They will be encrypted again; use Decrypt to open them.</Notice>
      )}

      <div className="card">
        <div className="card-title">
          <h2>Encrypt for</h2>
          <div className="actions">
            <div className="segmented">
              <button className={mode === 'keys' ? 'on' : ''} onClick={() => setMode('keys')}><I.KeyIcon /> Keys</button>
              <button className={mode === 'password' ? 'on' : ''} onClick={() => setMode('password')}><I.Lock /> Passphrase</button>
            </div>
          </div>
        </div>

        {mode === 'keys' ? (
          <>
            <span className="hint">
              Tick everyone who should be able to open the files. Each person decrypts with their own key, so
              nobody needs to share one.
            </span>
            {candidates.length === 0 ? (
              <Notice kind="info">You have no keys yet. Create one on the Keys page, or paste someone's public key below.</Notice>
            ) : (
              <div className="pick-list">
                {candidates.map((k) => (
                  <label className="pick-item" key={k.kind + k.name}>
                    <input type="checkbox" checked={chosen.includes(k.name)} onChange={() => toggle(k.name)} />
                    {k.kind === 'identity' ? <I.User className="icon faint" /> : <I.Users className="icon faint" />}
                    <div className="grow">
                      <span>{k.name}{k.kind === 'identity' && <span className="faint"> (you{k.default ? ', default' : ''})</span>}</span>
                      <span className="small faint mono ellipsis">{k.fingerprint}</span>
                    </div>
                    {k.postQuantum ? <span className="badge pq"><I.Atom /> Post-quantum</span> : <span className="badge">Classic</span>}
                  </label>
                ))}
              </div>
            )}
            {candidates.length > 0 && !(keyring?.contacts ?? []).some((k) => !k.error) && (
              <Notice kind="info">
                To encrypt for other people, import their public keys (contact cards) on the Keys page, or paste
                them below.
              </Notice>
            )}
            <label className="field">
              <span>Other public keys <span className="faint">(age1… or ssh-ed25519 / ssh-rsa keys, separated by spaces)</span></span>
              <input type="text" value={extra} spellCheck={false} onChange={(e) => setExtra(e.target.value)} placeholder="age1… or ssh-ed25519 AAAA…" className="mono" />
            </label>
            {badExtra.length > 0 && <Notice kind="error">Not a supported public key: {badExtra.join(', ')}</Notice>}
            {mixed && (
              <Notice kind="error">
                Post-quantum and classic keys can't be mixed in one file: the classic key would make the whole file
                only as strong as classic encryption. Choose one kind.
              </Notice>
            )}
            {!mixed && recipients.length > 0 && !allPQ && (
              <Notice kind="info">Classic keys are secure today but not against a future quantum computer.</Notice>
            )}
            {!chosen.some((n) => keyring?.identities.some((k) => k.name === n)) && recipients.length > 0 && (
              <Notice>You aren't one of the recipients, so you won't be able to decrypt these files yourself.</Notice>
            )}
          </>
        ) : (
          <>
            <NewPassphrase value={pass} onChange={setPass} confirm={pass2} onConfirm={setPass2} />
            <span className="hint">
              Anyone with the passphrase can decrypt the files. Passphrase encryption is symmetric, so it is not
              weakened by quantum computers — but a short passphrase can be guessed.
            </span>
          </>
        )}
      </div>

      <div className="card">
        <h2>Options</h2>
        <div className="row" style={{ alignItems: 'center' }}>
          <label className="check">
            <input type="checkbox" checked={sign} disabled={!signers.length} onChange={(e) => setSign(e.target.checked)} />
            Sign as
          </label>
          <select value={signAs} disabled={!sign} onChange={(e) => setSignAs(e.target.value)}>
            {signers.length === 0 && <option value="">No signing key</option>}
            {signers.map((k) => <option key={k.name} value={k.name}>{k.name}</option>)}
          </select>
          <span className="hint">Recipients can check the files came from you and weren't changed.</span>
        </div>
        <div className="row">
          <label className="check">
            <input type="checkbox" checked={armor} onChange={(e) => setArmor(e.target.checked)} />
            Text output (ASCII armour, for pasting into email)
          </label>
        </div>
        <div className="row">
          <label className="check">
            <input type="checkbox" checked={overwrite} onChange={(e) => setOverwrite(e.target.checked)} />
            Replace existing files without asking
          </label>
        </div>
        <OutputDir value={outputDir} onChange={setOutputDir} />
      </div>

      <div className="row">
        <span className="grow" />
        <button className="btn primary" disabled={!ready} onClick={go}>
          <I.Lock /> Encrypt {plainFiles.length > 0 ? `${plainFiles.length} file${plainFiles.length === 1 ? '' : 's'}` : ''}
        </button>
      </div>

      <Results results={results} onDismiss={() => setResults([])} />
    </div>
  )
}

const isSSH = (t: string) => /^(ssh-|ecdsa-sha2-|sk-ssh-|sk-ecdsa-)/.test(t)

// splitKeys splits pasted public keys into one string per key, as
// keys.SplitRecipients does: an SSH key keeps its type and key data and
// drops its comment, which runs up to the next key.
function splitKeys(text: string): string[] {
  const f = text.split(/[\s,;]+/).filter(Boolean)
  const out: string[] = []
  for (let i = 0; i < f.length; i++) {
    if (!isSSH(f[i])) {
      out.push(f[i])
      continue
    }
    let k = f[i]
    if (i + 1 < f.length) k += ' ' + f[++i]
    while (i + 1 < f.length && !f[i + 1].startsWith('age1') && !isSSH(f[i + 1])) i++
    out.push(k)
  }
  return out
}
