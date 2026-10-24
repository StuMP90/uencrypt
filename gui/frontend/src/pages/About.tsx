import { useEffect, useState } from 'react'
import { OpenKeyringFolder, Version } from '../../wailsjs/go/main/App'
import { BrowserOpenURL } from '../../wailsjs/runtime/runtime'
import { useApp } from '../components'
import logo from '../assets/logo.png'

const LICENCE = `MIT License

Copyright (c) 2026 Stuart Millington

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`

const link = (url: string, text: string) => <a onClick={() => BrowserOpenURL(url)}>{text}</a>

export default function AboutPage() {
  const { keyring, run } = useApp()
  const [version, setVersion] = useState('')
  useEffect(() => { Version().then(setVersion) }, [])

  return (
    <div className="page about">
      <div className="row" style={{ gap: 14 }}>
        <img src={logo} width={48} height={48} alt="" />
        <div>
          <h1>uEncrypt</h1>
          <p>Version {version}</p>
        </div>
      </div>

      <div className="card">
        <h2>File format</h2>
        <p>
          Files are encrypted with {link('https://age-encryption.org', 'age')}, an open, widely reviewed format, so
          they can also be opened with the <span className="mono">age</span> command-line tool and other compatible apps.
          New keys are post-quantum (ML-KEM-768 with X25519); passphrase encryption uses scrypt and is not affected by
          quantum computers. Signatures combine Ed25519 and post-quantum ML-DSA-65; both must be valid.
        </p>
        <p>
          Files made by the older encryption tools (<span className="mono">.enc</span>) can still be decrypted after
          importing their RSA key.
        </p>
      </div>

      <div className="card">
        <h2>Keyring</h2>
        <p>Your keys and contacts are stored in <span className="mono selectable">{keyring?.dir}</span>, shared with the
          {' '}<span className="mono">uencrypt</span> command line tool on the same account.</p>
        <div><button className="btn small" onClick={() => run(() => OpenKeyringFolder().then(() => true))}>Open folder</button></div>
      </div>

      <div className="card">
        <h2>Licence</h2>
        <div className="licence mono selectable">{LICENCE}</div>
        <p>Source code: {link('https://github.com/StuMP90/uencrypt', 'github.com/StuMP90/uencrypt')}</p>
      </div>
    </div>
  )
}
