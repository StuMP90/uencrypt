import { useEffect, useState } from 'react'
import { Cancel, InspectDetail, LookInside } from '../wailsjs/go/main/App'
import { content, inspect } from '../wailsjs/go/models'
import { errText, fmtSize } from './api'
import { Modal, Notice } from './components'
import * as I from './icons'

// listLimit is how many archive entries are shown; the backend lists up
// to 1000.
const listLimit = 200

// fmtTime formats a Go time, or '' for the zero time.
function fmtTime(t: string | undefined): string {
  if (!t) return ''
  const d = new Date(t)
  if (isNaN(d.getTime()) || d.getFullYear() < 1971) return ''
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

function signerName(s: inspect.Signature): string {
  if (s.own) return `${s.name} (your key)`
  if (s.known) return s.name || s.fingerprint
  return 'an unknown key ' + s.fingerprint
}

// InspectModal describes one file in detail. "Look inside…" decrypts it in
// memory to show what it holds; nothing is saved.
export function InspectModal({ path, onClose }: { path: string; onClose: () => void }) {
  const [rep, setRep] = useState<inspect.Report | null>(null)
  const [error, setError] = useState('')
  const [looking, setLooking] = useState(false)

  useEffect(() => {
    InspectDetail(path).then(setRep).catch((e) => setError(errText(e)))
  }, [path])

  const lookInside = async () => {
    setLooking(true)
    try {
      setRep(await LookInside(path))
    } catch (e) {
      if (errText(e) !== 'cancelled') setError(errText(e))
    } finally {
      setLooking(false)
    }
  }

  // Escape also answers a passphrase prompt, so it only closes this when idle.
  const close = () => { if (!looking) onClose() }
  const encrypted = rep?.kind === 'age' || rep?.kind === 'legacy'
  const looked = !!rep?.content && encrypted || !!rep?.contentsError

  return (
    <Modal title={rep?.name ?? 'Inspect'} onClose={close} wide>
      {error && <Notice kind="error">{error}</Notice>}
      {!rep && !error && <p>Reading…</p>}
      {rep && (
        <div className="inspect selectable">
          <dl className="kv">
            <dt>Type</dt>
            <dd>
              {rep.kind === 'plain' ? `${rep.content?.description}, not encrypted` : rep.format}
              {rep.postQuantum && <span className="badge pq"><I.Atom /> Post-quantum</span>}
            </dd>
            <dt>Size</dt><dd>{fmtSize(rep.fileSize)}</dd>
            {rep.kind === 'signature' && rep.signature && <>
              <dt>Signed by</dt><dd>{signerName(rep.signature)}</dd>
              <dt>Signed at</dt><dd>{fmtTime(rep.signature.signedAt)}</dd>
            </>}
            {rep.encryption && <><dt>Encryption</dt><dd>{rep.encryption}</dd></>}
            {!!rep.recipients?.length && <>
              <dt>Recipients</dt>
              <dd>{rep.recipients.map((r) => <div key={r.type}>{recipientText(r)}</div>)}</dd>
            </>}
            {!!rep.legacy?.chunks && <>
              <dt>Chunks</dt>
              <dd>{rep.legacy.chunks} of {fmtSize(rep.legacy.chunkSize ?? 0)}{rep.legacy.chunks > 1 && ' each (the last may be smaller)'}</dd>
            </>}
            {encrypted && <>
              <dt>Quantum-resistant</dt><dd>{rep.postQuantum ? 'Yes' : 'No'}</dd>
              <dt>For you</dt><dd>{rep.access}</dd>
            </>}
            {rep.sizes && <>
              <dt>Sizes</dt>
              <dd>
                {fmtSize(rep.sizes.payload)} of content (with any signature) + {fmtSize(rep.sizes.overhead)} overhead,
                of which the header is {fmtSize(rep.sizes.header)}
                {rep.armored && `; armored as text, the file is ${fmtSize(rep.fileSize)}`}
              </dd>
            </>}
            {rep.kind === 'age' && <>
              <dt>Signed</dt>
              <dd>
                {rep.signed === undefined ? 'Only known once decrypted'
                  : rep.signed && rep.signature ? `Yes, by ${signerName(rep.signature)} on ${fmtTime(rep.signature.signedAt)}`
                    : 'No'}
              </dd>
            </>}
            {looked && <>
              <dt>Contents</dt>
              <dd>
                {rep.contentsError ? <span className="error-text">Could not decrypt: {rep.contentsError}</span>
                  : `${rep.content!.description}, ${fmtSize(rep.content!.size)}`}
              </dd>
            </>}
            {rep.content && (rep.kind === 'plain' || looked) && !!rep.content.uncompressed && <>
              <dt>Uncompressed</dt><dd>{fmtSize(rep.content.uncompressed)}</dd>
            </>}
          </dl>

          {rep.content?.archive && <Entries c={rep.content} />}
          {rep.content?.notes?.map((n) => <Notice key={n} kind="info">{n}</Notice>)}
          {rep.warnings?.map((w) => <Notice key={w}>{w}</Notice>)}
        </div>
      )}
      <div className="modal-actions">
        {encrypted && !looked && (looking
          ? <button className="btn" onClick={() => Cancel()}>Stop</button>
          : <button className="btn" onClick={lookInside} title="Decrypt in memory to see what it holds; nothing is saved">
            <I.Eye /> Look inside…
          </button>)}
        <button className="btn primary" onClick={close} disabled={looking}>Close</button>
      </div>
    </Modal>
  )
}

function recipientText(r: inspect.Recipient): string {
  const who = [...(r.keys ?? [])]
  if (r.unidentified && r.type !== 'scrypt') who.push(`${r.unidentified} not identifiable`)
  return `${r.count} × ${r.description}` + (who.length ? ` (${who.join(', ')})` : '')
}

function Entries({ c }: { c: content.Report }) {
  const entries = c.entries ?? []
  const count = c.entryCount ?? entries.length
  return (
    <div className="entries">
      <div className="small muted">{count} entr{count === 1 ? 'y' : 'ies'}</div>
      <div className="entry-list">
        {entries.slice(0, listLimit).map((e, i) => (
          <div className="entry" key={i}>
            {e.dir ? <I.Folder /> : <I.File />}
            <span className="grow ellipsis" title={e.name}>{e.name}</span>
            <span className="muted">{e.dir ? '' : fmtSize(e.size)}</span>
            <span className="muted when">{fmtTime(e.modified)}</span>
          </div>
        ))}
        {count > Math.min(entries.length, listLimit) &&
          <div className="entry muted">… and {count - Math.min(entries.length, listLimit)} more</div>}
      </div>
    </div>
  )
}
