import { useEffect, useState } from 'react'
import { Inspect, PickFile, Sign, Verify } from '../../wailsjs/go/main/App'
import { main } from '../../wailsjs/go/models'
import { FileInfo, OpResult, baseName, errText } from '../api'
import { FilePicker, Notice, OutputDir, Results, fileDetail, useApp } from '../components'
import * as I from '../icons'

interface Props {
  files: FileInfo[]
  onAdd: (p: string[]) => void
  onRemove: (p: string) => void
  onClear: () => void
  verifyFile: FileInfo | null
  setVerifyFile: (f: FileInfo | null) => void
}

export default function SignPage({ verifyFile, setVerifyFile, ...props }: Props) {
  const { keyring, busy, run, toast } = useApp()
  const signers = (keyring?.identities ?? []).filter((k) => k.canSign && !k.error)
  const [signAs, setSignAs] = useState('')
  const [overwrite, setOverwrite] = useState(false)
  const [outputDir, setOutputDir] = useState('')
  const [results, setResults] = useState<OpResult[]>([])
  const [content, setContent] = useState('')
  const [verified, setVerified] = useState<OpResult | null>(null)

  useEffect(() => {
    if (!signAs && signers.length) setSignAs(signers.find((k) => k.default)?.name ?? signers[0].name)
  }, [signers, signAs])
  // A new signature file starts a fresh check against its default content.
  useEffect(() => {
    setVerified(null)
    setContent(verifyFile ? verifyFile.path.replace(/\.sig$/, '') : '')
  }, [verifyFile])

  const toSign = props.files.filter((f) => !f.error)

  const doSign = async () => {
    const r = await run(() => Sign(main.SignRequest.createFrom({ files: toSign.map((f) => f.path), signAs, outputDir, overwrite })))
    if (r) {
      setResults(r)
      const ok = r.filter((x) => x.ok).length
      if (ok) toast(`Signed ${ok} file${ok === 1 ? '' : 's'}.`, 'success')
      if (r.every((x) => x.ok)) props.onClear()
    }
  }

  const pickSig = async () => {
    try {
      const p = await PickFile('Choose a signature (.sig)')
      if (!p) return
      const [info] = await Inspect([p])
      if (info.kind !== 'signature') {
        toast(`${info.name} is not a uencrypt signature.`, 'error')
        return
      }
      setVerifyFile(info)
    } catch (e) {
      toast(errText(e), 'error')
    }
  }
  const pickContent = async () => {
    try {
      const p = await PickFile('Choose the signed file')
      if (p) { setContent(p); setVerified(null) }
    } catch (e) {
      toast(errText(e), 'error')
    }
  }
  const doVerify = async () => {
    if (!verifyFile) return
    const r = await run(() => Verify(main.VerifyRequest.createFrom({ sigFile: verifyFile.path, content })))
    if (r) setVerified(r)
  }

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1>Sign &amp; Verify</h1>
          <p>A signature proves a file came from you and hasn't been changed, without encrypting it.</p>
        </div>
      </div>

      <div className="split">
        <div className="card">
          <div className="card-title"><I.Pen className="icon faint" /><h2>Sign files</h2></div>
          <FilePicker {...props} hint="Drop files here to sign them" pickTitle="Choose files to sign" />
          {signers.length === 0 ? (
            <Notice kind="info">You need a key with signing to sign files. Create one on the Keys page.</Notice>
          ) : (
            <label className="field">
              <span>Sign as</span>
              <select value={signAs} onChange={(e) => setSignAs(e.target.value)}>
                {signers.map((k) => <option key={k.name} value={k.name}>{k.name}</option>)}
              </select>
            </label>
          )}
          <label className="check">
            <input type="checkbox" checked={overwrite} onChange={(e) => setOverwrite(e.target.checked)} />
            Replace existing signatures without asking
          </label>
          <OutputDir value={outputDir} onChange={setOutputDir} />
          <span className="hint">Each file gets a separate .sig file; send both.</span>
          <div className="row">
            <span className="grow" />
            <button className="btn primary" disabled={busy || !toSign.length || !signAs} onClick={doSign}><I.Pen /> Sign</button>
          </div>
        </div>

        <div className="card">
          <div className="card-title"><I.Shield className="icon faint" /><h2>Verify a signature</h2></div>
          {verifyFile ? (
            <div className="file-list">
              <div className="file-row">
                <I.Pen />
                <div className="grow">
                  <div className="name ellipsis" title={verifyFile.path}>{verifyFile.name}</div>
                  <div className="detail ellipsis">{verifyFile.error || fileDetail(verifyFile)}</div>
                </div>
                <button className="btn ghost icon-btn" title="Clear" onClick={() => setVerifyFile(null)}><I.X /></button>
              </div>
            </div>
          ) : (
            <div className="dropzone">
              <I.Shield />
              <div>Drop a .sig file anywhere in the window</div>
              <button className="btn" onClick={pickSig}>Choose signature…</button>
            </div>
          )}
          <label className="field">
            <span>Signed file</span>
            <div className="row" style={{ flexWrap: 'nowrap' }}>
              <div className="grow ellipsis" title={content} style={{ color: content ? 'var(--text-0)' : 'var(--text-2)' }}>
                {content ? baseName(content) : 'None chosen'}
              </div>
              <button className="btn small" onClick={pickContent}><I.File /> Choose…</button>
            </div>
          </label>
          <div className="row">
            <span className="grow" />
            <button className="btn primary" disabled={busy || !verifyFile || !content} onClick={doVerify}><I.Shield /> Verify</button>
          </div>
          {verified && <VerifyResult r={verified} />}
        </div>
      </div>

      <Results results={results} onDismiss={() => setResults([])} />
    </div>
  )
}

function VerifyResult({ r }: { r: OpResult }) {
  if (!r.ok) {
    return (
      <Notice kind="error">
        {r.skipped ? 'Cancelled.' : <><b>Signature check failed.</b> {r.error}. The file may have been changed, or the signature is for a different file.</>}
      </Notice>
    )
  }
  const s = r.signer
  return (
    <div className={'notice ' + (s?.known ? 'info' : '')} style={s?.known ? { color: 'var(--success)', background: 'rgba(95,191,111,.1)' } : undefined}>
      {s?.known ? <I.CheckCircle /> : <I.Alert />}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
        <b>{s?.known ? `Valid signature from ${s.name}${s.own ? ' (you)' : ''}` : 'Valid signature from an unknown key'}</b>
        {r.signedAt && <span>Signed {r.signedAt}</span>}
        <span className="mono selectable">{s?.fingerprint}</span>
        {r.warnings?.map((w, i) => <span key={i}>{w}</span>)}
      </div>
    </div>
  )
}
