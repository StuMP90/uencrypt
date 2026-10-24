import { useEffect, useState } from 'react'
import { AddSSHKey, Decrypt, RemoveSSHKey, SSHKeys } from '../../wailsjs/go/main/App'
import { main } from '../../wailsjs/go/models'
import { FileInfo, OpResult, baseName, errText } from '../api'
import { FilePicker, Notice, OutputDir, Results, useApp } from '../components'
import * as I from '../icons'

interface Props {
  files: FileInfo[]
  onAdd: (p: string[]) => void
  onRemove: (p: string) => void
  onClear: () => void
}

export default function DecryptPage(props: Props) {
  const { keyring, busy, run, toast } = useApp()
  const [requireSigner, setRequireSigner] = useState('')
  const [overwrite, setOverwrite] = useState(false)
  const [outputDir, setOutputDir] = useState('')
  const [results, setResults] = useState<OpResult[]>([])
  const [sshKeys, setSSHKeys] = useState<string[]>([])

  useEffect(() => { SSHKeys().then((k) => setSSHKeys(k ?? [])) }, [])
  const addSSH = () => AddSSHKey().then(() => SSHKeys()).then((k) => setSSHKeys(k ?? [])).catch((e) => toast(errText(e), 'error'))
  const removeSSH = (p: string) => RemoveSSHKey(p).then(() => setSSHKeys((k) => k.filter((x) => x !== p)))

  const encrypted = props.files.filter((f) => f.kind === 'age' || f.kind === 'legacy')
  const others = props.files.filter((f) => !encrypted.includes(f))
  const signers = [...(keyring?.contacts ?? []), ...(keyring?.identities ?? [])].filter((k) => k.canSign && !k.error)
  const hasLegacy = encrypted.some((f) => f.kind === 'legacy')

  const go = async () => {
    const req = main.DecryptRequest.createFrom({
      files: encrypted.map((f) => f.path), outputDir, requireSigner, overwrite,
    })
    const r = await run(() => Decrypt(req))
    if (r) {
      setResults(r)
      const ok = r.filter((x) => x.ok).length
      if (ok) toast(`Decrypted ${ok} file${ok === 1 ? '' : 's'}.`, 'success')
      if (r.every((x) => x.ok)) props.onClear()
    }
  }

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1>Decrypt</h1>
          <p>Open .age files, and .enc files from the older tools. You'll be asked for a passphrase if one is needed.</p>
        </div>
      </div>

      <FilePicker {...props} hint="Drop encrypted files here (.age, .enc)" pickTitle="Choose files to decrypt" />

      {others.length > 0 && (
        <Notice>
          {others.length === 1 ? `${others[0].name} isn't` : `${others.length} files aren't`} encrypted and will be
          skipped.
        </Notice>
      )}
      {hasLegacy && keyring && keyring.legacy.length === 0 && (
        <Notice>Old-format files need the RSA private key (.pem) they were made with. Import it on the Keys page.</Notice>
      )}

      <div className="card">
        <h2>Options</h2>
        <label className="field">
          <span>Require a signature from</span>
          <select value={requireSigner} onChange={(e) => setRequireSigner(e.target.value)}>
            <option value="">Nobody (signatures are still checked if present)</option>
            {signers.map((k) => <option key={k.kind + k.name} value={k.name}>{k.name}</option>)}
          </select>
          <span className="hint">
            When set, a file is only saved if it was signed by this key — use it to be sure a file really came from them.
          </span>
        </label>
        <label className="check">
          <input type="checkbox" checked={overwrite} onChange={(e) => setOverwrite(e.target.checked)} />
          Replace existing files without asking
        </label>
        <OutputDir value={outputDir} onChange={setOutputDir} />
        <div className="field">
          <span>SSH keys</span>
          {sshKeys.length > 0 && (
            <div className="file-rows">
              {sshKeys.map((p) => (
                <div className="file-row" key={p}>
                  <I.KeyIcon />
                  <div className="grow"><span className="name ellipsis" title={p}>{baseName(p)}</span></div>
                  <button className="btn ghost icon-btn" title="Don't use this key" onClick={() => removeSSH(p)}><I.X /></button>
                </div>
              ))}
            </div>
          )}
          <div className="row">
            <button className="btn small" onClick={addSSH}><I.KeyIcon /> Use an SSH key…</button>
          </div>
          <span className="hint">
            For files encrypted to an SSH public key. ~/.ssh/id_ed25519 and id_rsa are tried automatically; choose
            another private key here. It stays where it is and is only used until you close the app.
          </span>
        </div>
      </div>

      <div className="row">
        <span className="grow" />
        <button className="btn primary" disabled={busy || !encrypted.length} onClick={go}>
          <I.Unlock /> Decrypt {encrypted.length > 0 ? `${encrypted.length} file${encrypted.length === 1 ? '' : 's'}` : ''}
        </button>
      </div>

      <Results results={results} onDismiss={() => setResults([])} />
    </div>
  )
}
