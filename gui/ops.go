package main

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/StuMP90/uencrypt/internal/envelope"
	"github.com/StuMP90/uencrypt/internal/fileio"
	"github.com/StuMP90/uencrypt/internal/keys"
	"github.com/StuMP90/uencrypt/internal/sign"
)

// SignerInfo names who made a signature.
type SignerInfo struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	Known       bool   `json:"known"`
	Own         bool   `json:"own"`
}

func signerInfo(kr *keys.Keyring, pk *sign.PublicKey) *SignerInfo {
	if pk == nil {
		return nil
	}
	s := &SignerInfo{Fingerprint: pk.Fingerprint()}
	s.Name, s.Own, s.Known = kr.SignerName(pk)
	return s
}

func (s *SignerInfo) String() string {
	switch {
	case s.Own:
		return fmt.Sprintf("%s [your key] (%s)", s.Name, s.Fingerprint)
	case s.Known:
		return fmt.Sprintf("%s (%s)", s.Name, s.Fingerprint)
	}
	return "an unknown key " + s.Fingerprint
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

// FileInfo is what the file list shows about a selected file.
type FileInfo struct {
	Path string `json:"path"`
	Name string `json:"name"`
	Size int64  `json:"size"`
	// Kind is "plain", "age", "legacy" or "signature".
	Kind          string      `json:"kind"`
	KindLabel     string      `json:"kindLabel"`
	Recipients    []string    `json:"recipients"`
	PostQuantum   bool        `json:"postQuantum"`
	LegacyKeyBits int         `json:"legacyKeyBits"`
	Signer        *SignerInfo `json:"signer"`
	SignedAt      string      `json:"signedAt"`
	Error         string      `json:"error"`
}

// Inspect describes files without decrypting them.
func (a *App) Inspect(paths []string) []FileInfo {
	kr, _ := a.keyring()
	out := make([]FileInfo, 0, len(paths))
	for _, p := range paths {
		out = append(out, inspectFile(kr, p))
	}
	return out
}

func inspectFile(kr *keys.Keyring, path string) FileInfo {
	fi := FileInfo{Path: path, Name: filepath.Base(path), Kind: "plain", KindLabel: "File", Recipients: []string{}}
	st, err := os.Stat(path)
	if err != nil {
		fi.Error = err.Error()
		return fi
	}
	if st.IsDir() {
		fi.Error = "folders cannot be encrypted directly: archive it first (for example as .zip or .tar.gz)"
		return fi
	}
	fi.Size = st.Size()
	f, err := os.Open(path)
	if err != nil {
		fi.Error = err.Error()
		return fi
	}
	defer f.Close()
	info, err := envelope.Inspect(f)
	if errors.Is(err, envelope.ErrUnknownFormat) {
		return fi
	}
	switch info.Kind {
	case envelope.KindAge, envelope.KindAgeArmored:
		fi.Kind, fi.KindLabel = "age", "Encrypted"
		if info.Kind == envelope.KindAgeArmored {
			fi.KindLabel = "Encrypted (text)"
		}
	case envelope.KindLegacy:
		fi.Kind, fi.KindLabel = "legacy", "Encrypted (old format)"
	case envelope.KindSignature:
		fi.Kind, fi.KindLabel = "signature", "Signature"
	}
	if err != nil {
		fi.Error = err.Error()
		return fi
	}
	for _, s := range info.Stanzas {
		fi.Recipients = append(fi.Recipients, envelope.DescribeStanza(s))
	}
	fi.PostQuantum = info.PostQuantum
	fi.LegacyKeyBits = info.LegacyKeyBits
	if kr != nil {
		fi.Signer = signerInfo(kr, info.Signer)
	}
	fi.SignedAt = formatTime(info.SignedAt)
	return fi
}

// OpResult reports one file of an operation.
type OpResult struct {
	Input    string      `json:"input"`
	Output   string      `json:"output"`
	OK       bool        `json:"ok"`
	Skipped  bool        `json:"skipped"`
	Error    string      `json:"error"`
	Warnings []string    `json:"warnings"`
	Format   string      `json:"format"`
	Signed   bool        `json:"signed"`
	Signer   *SignerInfo `json:"signer"`
	SignedAt string      `json:"signedAt"`
}

// progress emits "progress" events for one file, at most every 100ms.
func (a *App) progress(file string, total int64) envelope.Progress {
	var last time.Time
	return func(done int64) {
		if now := time.Now(); now.Sub(last) >= 100*time.Millisecond || done == total {
			last = now
			wruntime.EventsEmit(a.ctx, "progress", map[string]any{"file": file, "done": done, "total": total})
		}
	}
}

var errSkipped = errors.New("skipped")

// create opens dst for writing, asking before replacing an existing file
// unless overwrite is set. It returns errSkipped if the user says no.
func (a *App) create(ctx context.Context, dst string, overwrite bool, perm os.FileMode) (*fileio.Output, error) {
	o, err := fileio.Create(dst, overwrite, perm)
	if errors.Is(err, fileio.ErrExists) {
		if !a.confirm(ctx, "Replace file?", fmt.Sprintf("“%s” already exists in %s. Replace it?", filepath.Base(dst), filepath.Dir(dst)), "Replace") {
			if ctx.Err() != nil {
				return nil, errCancelled
			}
			return nil, errSkipped
		}
		return fileio.Create(dst, true, perm)
	}
	return o, err
}

func outputPath(dir, name string) string {
	if dir == "" {
		return name
	}
	return filepath.Join(dir, filepath.Base(name))
}

// run applies fn to each file in turn. After a cancel, the remaining files
// are reported as skipped.
func (a *App) run(ctx context.Context, files []string, fn func(in string, r *OpResult) error) []OpResult {
	results := make([]OpResult, 0, len(files))
	for _, in := range files {
		r := OpResult{Input: in, Warnings: []string{}}
		if ctx.Err() != nil {
			r.Skipped, r.Error = true, "cancelled"
			results = append(results, r)
			continue
		}
		wruntime.EventsEmit(a.ctx, "progress", map[string]any{"file": in, "done": 0, "total": 0})
		err := fn(in, &r)
		switch {
		case errors.Is(err, errSkipped):
			r.Skipped, r.Error = true, "not replaced"
		case err != nil && ctx.Err() != nil:
			r.Skipped, r.Error = true, "cancelled"
		case err != nil:
			r.Error = err.Error()
		default:
			r.OK = true
		}
		results = append(results, r)
	}
	return results
}

func fileSize(f *os.File) int64 {
	if st, err := f.Stat(); err == nil {
		return st.Size()
	}
	return 0
}

// --- encrypt ---------------------------------------------------------------

type EncryptRequest struct {
	Files     []string `json:"files"`
	OutputDir string   `json:"outputDir"`
	// Mode is "keys" or "password".
	Mode string `json:"mode"`
	// Recipients are keyring names, or age1... or SSH public keys.
	Recipients []string `json:"recipients"`
	Passphrase string   `json:"passphrase"`
	Sign       bool     `json:"sign"`
	// SignAs is the identity to sign with; empty means the default.
	SignAs    string `json:"signAs"`
	Armor     bool   `json:"armor"`
	Overwrite bool   `json:"overwrite"`
}

func (a *App) Encrypt(req EncryptRequest) ([]OpResult, error) {
	ctx, done, err := a.begin()
	if err != nil {
		return nil, err
	}
	defer done()
	kr, err := a.keyring()
	if err != nil {
		return nil, err
	}
	opts := envelope.EncryptOptions{Armor: req.Armor}
	switch req.Mode {
	case "password":
		if req.Passphrase == "" {
			return nil, errors.New("enter a passphrase")
		}
		opts.Passphrase = req.Passphrase
	case "keys":
		if opts.Recipients, err = resolveRecipients(kr, req.Recipients); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown mode %q", req.Mode)
	}
	if req.Sign {
		id, err := a.signingIdentity(ctx, kr, req.SignAs)
		if err != nil {
			return nil, err
		}
		opts.Signer = id.Signer
	}
	return a.run(ctx, req.Files, func(in string, r *OpResult) error {
		r.Output = outputPath(req.OutputDir, fileio.EncryptedName(in))
		r.Signed = opts.Signer != nil
		f, err := os.Open(in)
		if err != nil {
			return err
		}
		defer f.Close()
		o, err := a.create(ctx, r.Output, req.Overwrite, 0o644)
		if err != nil {
			return err
		}
		defer o.Abort()
		opts.Progress = a.progress(in, fileSize(f))
		if err := envelope.Encrypt(ctx, f, o, opts); err != nil {
			return err
		}
		return o.Commit()
	}), nil
}

// resolveRecipients turns names and public keys into recipients, refusing
// a mix of post-quantum and classic keys (the file would only be as strong
// as the classic one). No names means the default identity.
func resolveRecipients(kr *keys.Keyring, names []string) ([]age.Recipient, error) {
	if len(names) == 0 {
		def, err := kr.DefaultIdentity()
		if err != nil {
			return nil, errors.New("choose at least one recipient, or create a key first")
		}
		names = []string{def}
	}
	var out []age.Recipient
	var classic []string
	for _, n := range names {
		var r age.Recipient
		if strings.HasPrefix(n, "age1") || keys.IsSSHRecipient(n) {
			var err error
			if r, err = keys.ParseRecipient(n); err != nil {
				return nil, err
			}
		} else {
			c, err := kr.Recipient(n)
			if err != nil {
				return nil, err
			}
			r = c.Recipient
		}
		if keys.StanzaType(r) != "mlkem768x25519" {
			if keys.IsSSHRecipient(n) {
				classic = append(classic, strings.Fields(n)[0]+" key")
			} else {
				classic = append(classic, n)
			}
		}
		out = append(out, r)
	}
	if len(classic) > 0 && len(classic) < len(out) {
		return nil, fmt.Errorf("cannot mix post-quantum and classic keys in one file (classic: %s); "+
			"ask them for a post-quantum key or encrypt separate copies", strings.Join(classic, ", "))
	}
	return out, nil
}

func (a *App) signingIdentity(ctx context.Context, kr *keys.Keyring, name string) (*keys.Identity, error) {
	if name == "" {
		var err error
		if name, err = kr.DefaultIdentity(); err != nil {
			return nil, errors.New("signing needs a key of your own: create one on the Keys page")
		}
	}
	id, err := kr.LoadIdentity(name, a.unlocker(ctx))
	if err != nil {
		return nil, err
	}
	if id.Signer == nil {
		return nil, fmt.Errorf("the key “%s” cannot sign (it was imported from a plain age key)", name)
	}
	return id, nil
}

// --- decrypt ---------------------------------------------------------------

type DecryptRequest struct {
	Files     []string `json:"files"`
	OutputDir string   `json:"outputDir"`
	// RequireSigner, if set, fails files not signed by this keyring name.
	RequireSigner string `json:"requireSigner"`
	Overwrite     bool   `json:"overwrite"`
}

func (a *App) Decrypt(req DecryptRequest) ([]OpResult, error) {
	ctx, done, err := a.begin()
	if err != nil {
		return nil, err
	}
	defer done()
	kr, err := a.keyring()
	if err != nil {
		return nil, err
	}
	var want *sign.PublicKey
	if req.RequireSigner != "" {
		c, err := kr.Recipient(req.RequireSigner)
		if err != nil {
			return nil, err
		}
		if c.Signer == nil {
			return nil, fmt.Errorf("“%s” has no signing key", req.RequireSigner)
		}
		want = c.Signer
	}
	ids, err := kr.DecryptionIdentities(a.unlocker(ctx))
	if err != nil {
		return nil, err
	}
	sshIDs, err := a.sshIdentities(ctx)
	if err != nil {
		return nil, err
	}
	ids = append(ids, sshIDs...)
	// Legacy keys are read once, on the first old-format file.
	var legacyOnce sync.Once
	var legacyKeys []*rsa.PrivateKey
	var legacyErr error
	loadLegacy := func() ([]*rsa.PrivateKey, error) {
		legacyOnce.Do(func() { legacyKeys, legacyErr = kr.LegacyKeys() })
		if len(legacyKeys) == 0 {
			return nil, legacyErr
		}
		return legacyKeys, nil
	}

	return a.run(ctx, req.Files, func(in string, r *OpResult) error {
		r.Output = outputPath(req.OutputDir, fileio.DecryptedName(in))
		f, err := os.Open(in)
		if err != nil {
			return err
		}
		defer f.Close()
		o, err := a.create(ctx, r.Output, req.Overwrite, 0o600)
		if err != nil {
			return err
		}
		defer o.Abort()
		tries := 0
		opts := envelope.DecryptOptions{
			Identities: ids,
			LegacyKeys: loadLegacy,
			Progress:   a.progress(in, fileSize(f)),
			Passphrase: func() (string, error) {
				p := Prompt{Kind: "passphrase", Title: "Passphrase", Confirm: "Decrypt",
					Message: fmt.Sprintf("“%s” is protected with a passphrase.", filepath.Base(in))}
				if tries > 0 {
					p.Error = "Incorrect passphrase, try again."
				}
				tries++
				return a.ask(ctx, p)
			},
		}
		res, err := envelope.Decrypt(ctx, f, o, opts)
		if res != nil {
			r.Format, r.Signed, r.Signer = res.Format, res.Signed, signerInfo(kr, res.Signer)
			r.SignedAt = formatTime(res.SignedAt)
		}
		if err != nil {
			if errors.Is(err, sign.ErrBadSignature) && r.Signer != nil {
				return fmt.Errorf("%w (claimed signer %s); nothing was written", err, r.Signer)
			}
			return err
		}
		if want != nil {
			switch {
			case !res.Signed:
				return errors.New("the file is not signed, but a signature was required; nothing was written")
			case !res.Signer.Equal(want):
				return fmt.Errorf("signed by %s, not by %s; nothing was written", r.Signer, req.RequireSigner)
			}
		}
		if err := o.Commit(); err != nil {
			return err
		}
		r.Warnings = append(r.Warnings, res.Warnings...)
		if res.Signed && !r.Signer.Known {
			r.Warnings = append(r.Warnings, "The signature is valid, but the signer "+r.Signer.Fingerprint+
				" is not in your keyring, so who made it cannot be confirmed.")
		}
		return nil
	}), nil
}

// --- sign and verify -------------------------------------------------------

type SignRequest struct {
	Files     []string `json:"files"`
	SignAs    string   `json:"signAs"`
	OutputDir string   `json:"outputDir"`
	Overwrite bool     `json:"overwrite"`
}

func (a *App) Sign(req SignRequest) ([]OpResult, error) {
	ctx, done, err := a.begin()
	if err != nil {
		return nil, err
	}
	defer done()
	kr, err := a.keyring()
	if err != nil {
		return nil, err
	}
	id, err := a.signingIdentity(ctx, kr, req.SignAs)
	if err != nil {
		return nil, err
	}
	signer := signerInfo(kr, id.Signer.Public())
	return a.run(ctx, req.Files, func(in string, r *OpResult) error {
		r.Output = outputPath(req.OutputDir, fileio.SignatureName(in))
		f, err := os.Open(in)
		if err != nil {
			return err
		}
		defer f.Close()
		pr := &progressReader{r: f, ctx: ctx, fn: a.progress(in, fileSize(f))}
		now := time.Now()
		sig, err := sign.SignDetached(id.Signer, pr, now)
		if err != nil {
			return err
		}
		o, err := a.create(ctx, r.Output, req.Overwrite, 0o644)
		if err != nil {
			return err
		}
		defer o.Abort()
		if _, err := o.Write(sig); err != nil {
			return err
		}
		r.Signed, r.Signer, r.SignedAt = true, signer, formatTime(now)
		return o.Commit()
	}), nil
}

type VerifyRequest struct {
	SigFile string `json:"sigFile"`
	// Content is the signed file; empty means SigFile without ".sig".
	Content string `json:"content"`
}

// Verify checks a detached signature. A bad signature is reported in the
// result, not as an error.
func (a *App) Verify(req VerifyRequest) (*OpResult, error) {
	ctx, done, err := a.begin()
	if err != nil {
		return nil, err
	}
	defer done()
	kr, err := a.keyring()
	if err != nil {
		return nil, err
	}
	if req.Content == "" {
		var ok bool
		if req.Content, ok = strings.CutSuffix(req.SigFile, ".sig"); !ok {
			return nil, errors.New("choose the file that was signed")
		}
	}
	r := &OpResult{Input: req.Content, Output: req.SigFile, Warnings: []string{}}
	sigText, err := fileio.ReadSmallFile(req.SigFile)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(req.Content)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h, err := sign.VerifyDetached(sigText, &progressReader{r: f, ctx: ctx, fn: a.progress(req.Content, fileSize(f))})
	if err != nil {
		if ctx.Err() != nil {
			r.Skipped, r.Error = true, "cancelled"
		} else {
			r.Error = err.Error()
		}
		return r, nil
	}
	r.OK, r.Signed = true, true
	r.Signer, r.SignedAt = signerInfo(kr, h.Signer), formatTime(h.Created)
	if !r.Signer.Known {
		r.Warnings = append(r.Warnings, "The signature is valid, but the signer "+r.Signer.Fingerprint+
			" is not in your keyring, so who made it cannot be confirmed. Import their contact card and check the fingerprint with them.")
	}
	return r, nil
}

// progressReader reports bytes read and stops when ctx is cancelled.
type progressReader struct {
	r   io.Reader
	ctx context.Context
	fn  envelope.Progress
	n   int64
}

func (p *progressReader) Read(b []byte) (int, error) {
	if err := p.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := p.r.Read(b)
	p.n += int64(n)
	p.fn(p.n)
	return n, err
}
