// Package envelope is the format-level API shared by the CLI and GUI: it
// detects what a file is, encrypts (optionally signing) to age, and
// decrypts age, signed-and-encrypted and legacy files.
package envelope

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/StuMP90/uencrypt/internal/legacy"
	"github.com/StuMP90/uencrypt/internal/sign"
)

// Kind is what Detect thinks a file is.
type Kind int

const (
	KindUnknown Kind = iota
	KindAge
	KindAgeArmored
	KindLegacy
	KindSignature // detached uencrypt signature
)

func (k Kind) String() string {
	switch k {
	case KindAge:
		return "age"
	case KindAgeArmored:
		return "age (armored)"
	case KindLegacy:
		return "legacy"
	case KindSignature:
		return "uencrypt signature"
	}
	return "unknown"
}

const (
	ageMagic       = "age-encryption.org/"
	signatureBegin = "-----BEGIN UENCRYPT SIGNATURE-----"
	// PeekSize is enough of a file's start for Detect.
	PeekSize = 64
)

// Detect identifies a file from its first PeekSize bytes.
func Detect(prefix []byte) Kind {
	t := bytes.TrimLeft(prefix, " \t\r\n")
	switch {
	case bytes.HasPrefix(prefix, []byte(ageMagic)):
		return KindAge
	case bytes.HasPrefix(t, []byte(armor.Header)):
		return KindAgeArmored
	case bytes.HasPrefix(t, []byte(signatureBegin)):
		return KindSignature
	case legacy.Sniff(prefix):
		return KindLegacy
	}
	return KindUnknown
}

var (
	// ErrUnknownFormat means the input is not a format uencrypt can decrypt.
	ErrUnknownFormat = errors.New("not an encrypted file uencrypt recognises")
	// ErrNoKey means none of the available keys or passphrases can decrypt
	// the file.
	ErrNoKey = errors.New("no matching key")
)

// Progress is called with the cumulative number of input bytes processed.
type Progress func(done int64)

// ctxReader stops reading when ctx is cancelled and reports progress.
type ctxReader struct {
	ctx      context.Context
	r        io.Reader
	n        int64
	progress Progress
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.progress != nil && n > 0 {
		c.progress(c.n)
	}
	return n, err
}

// EncryptOptions configures Encrypt. Exactly one of Recipients or
// Passphrase must be set.
type EncryptOptions struct {
	Recipients []age.Recipient
	Passphrase string
	// Signer, if set, signs the content inside the encryption.
	Signer   *sign.SecretKey
	Armor    bool
	Progress Progress
}

// Encrypt encrypts src to dst. Without a signer the output is a plain age
// file that any age implementation can decrypt.
func Encrypt(ctx context.Context, src io.Reader, dst io.Writer, opts EncryptOptions) error {
	var recips []age.Recipient
	switch {
	case opts.Passphrase != "" && len(opts.Recipients) > 0:
		return errors.New("use either recipients or a passphrase, not both")
	case opts.Passphrase != "":
		r, err := age.NewScryptRecipient(opts.Passphrase)
		if err != nil {
			return err
		}
		recips = []age.Recipient{r}
	case len(opts.Recipients) > 0:
		recips = opts.Recipients
	default:
		return errors.New("no recipients or passphrase")
	}

	out := dst
	var aw io.WriteCloser
	if opts.Armor {
		aw = armor.NewWriter(dst)
		out = aw
	}
	ew, err := age.Encrypt(out, recips...)
	if err != nil {
		return err
	}
	var w io.Writer = ew
	var sw io.WriteCloser
	if opts.Signer != nil {
		if sw, err = sign.NewSigningWriter(ew, opts.Signer, time.Now()); err != nil {
			return err
		}
		w = sw
	}
	if _, err := io.Copy(w, &ctxReader{ctx: ctx, r: src, progress: opts.Progress}); err != nil {
		return err
	}
	if sw != nil {
		if err := sw.Close(); err != nil {
			return err
		}
	}
	if err := ew.Close(); err != nil {
		return err
	}
	if aw != nil {
		return aw.Close()
	}
	return nil
}

// DecryptOptions supplies the keys Decrypt may use. Every source is
// consulted only if the file needs it.
type DecryptOptions struct {
	// Identities are age identities, typically lazy keyring identities.
	Identities []age.Identity
	// Passphrase is asked for passphrase-encrypted files. It is called again
	// after a wrong passphrase, up to three times; returning an error stops.
	Passphrase func() (string, error)
	// LegacyKeys returns RSA keys for old ppkencrypt/oakcryptor files.
	LegacyKeys func() ([]*rsa.PrivateKey, error)
	Progress   Progress
}

// Result describes a successful (or signature-failed) decryption.
type Result struct {
	Format   string // "age", "age (armored)", "legacy-original", "legacy-chunked"
	Stanzas  []string
	Signed   bool
	Signer   *sign.PublicKey
	SignedAt time.Time
	Warnings []string
}

// Decrypt decrypts src into dst.
//
// dst receives plaintext as it is decrypted, before the age payload or
// signature has been fully checked, so on any error the caller must discard
// what was written (the CLI and GUI write to a temporary file and rename it
// only on success).
//
// For a signed file whose signature does not verify, the error wraps
// sign.ErrBadSignature and the Result still identifies the claimed signer.
func Decrypt(ctx context.Context, src io.Reader, dst io.Writer, opts DecryptOptions) (*Result, error) {
	br := bufio.NewReaderSize(&ctxReader{ctx: ctx, r: src, progress: opts.Progress}, 64*1024)
	prefix, _ := br.Peek(PeekSize)
	kind := Detect(prefix)
	switch kind {
	case KindAge, KindAgeArmored:
		return decryptAge(br, dst, kind, opts)
	case KindLegacy:
		return decryptLegacy(br, dst, opts)
	case KindSignature:
		return nil, errors.New("this is a detached signature, not an encrypted file: use verify")
	}
	if len(prefix) == 0 {
		return nil, fmt.Errorf("%w (empty input)", ErrUnknownFormat)
	}
	return nil, ErrUnknownFormat
}

func decryptAge(src io.Reader, dst io.Writer, kind Kind, opts DecryptOptions) (*Result, error) {
	if kind == KindAgeArmored {
		src = armor.NewReader(src)
	}
	ids := slices.Clone(opts.Identities)
	if opts.Passphrase != nil {
		ids = append(ids, &passphraseIdentity{ask: opts.Passphrase})
	}
	res := &Result{Format: kind.String()}
	ids = append(ids, &stanzaRecorder{res: res})
	if len(ids) == 1 {
		return nil, fmt.Errorf("%w: no identities or passphrase available", ErrNoKey)
	}
	r, err := age.Decrypt(src, ids...)
	if err != nil {
		var nm *age.NoIdentityMatchError
		if errors.As(err, &nm) {
			return res, fmt.Errorf("%w for this file (%s)%s", ErrNoKey, strings.Join(nm.StanzaTypes, ", "), reasons(nm.Errors))
		}
		return res, err
	}

	pr := bufio.NewReaderSize(r, 64*1024)
	if p, _ := pr.Peek(len(sign.EmbeddedMagic)); sign.IsEmbedded(p) {
		h, err := sign.VerifyEmbedded(pr, dst)
		res.Signed = h != nil
		if h != nil {
			res.Signer, res.SignedAt = h.Signer, h.Created
		}
		return res, err
	}
	_, err = io.Copy(dst, pr)
	return res, err
}

// reasons summarises why identities failed, skipping the uninformative
// "wrong key type" errors.
func reasons(errs []error) string {
	var out []string
	for _, e := range errs {
		msg := e.Error()
		if msg == age.ErrIncorrectIdentity.Error() || strings.Contains(msg, "not passphrase-encrypted") || errors.Is(e, errRecorder) {
			continue
		}
		msg = strings.TrimPrefix(msg, age.ErrIncorrectIdentity.Error()+": ")
		if !slices.Contains(out, msg) {
			out = append(out, msg)
		}
	}
	if len(out) == 0 {
		return ""
	}
	return ": " + strings.Join(out, "; ")
}

var errRecorder = fmt.Errorf("%w: (recorder)", age.ErrIncorrectIdentity)

// stanzaRecorder is a pseudo-identity, always tried last, that records the
// file's recipient types for the Result.
type stanzaRecorder struct{ res *Result }

func (s *stanzaRecorder) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	s.res.Stanzas = stanzaTypes(stanzas)
	return nil, errRecorder
}

func stanzaTypes(stanzas []*age.Stanza) []string {
	var t []string
	for _, s := range stanzas {
		if !slices.Contains(t, s.Type) {
			t = append(t, s.Type)
		}
	}
	return t
}

// passphraseIdentity asks for a passphrase only for scrypt files, retrying
// a wrong one.
type passphraseIdentity struct {
	ask func() (string, error)
}

func (p *passphraseIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if !slices.ContainsFunc(stanzas, func(s *age.Stanza) bool { return s.Type == "scrypt" }) {
		return nil, age.ErrIncorrectIdentity
	}
	var lastErr error = age.ErrIncorrectIdentity
	for range 3 {
		pass, err := p.ask()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", age.ErrIncorrectIdentity, err)
		}
		id, err := age.NewScryptIdentity(pass)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", age.ErrIncorrectIdentity, err)
		}
		key, err := id.Unwrap(stanzas)
		if err == nil {
			return key, nil
		}
		if !errors.Is(err, age.ErrIncorrectIdentity) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

func decryptLegacy(src io.Reader, dst io.Writer, opts DecryptOptions) (*Result, error) {
	var keys []*rsa.PrivateKey
	var loadErr error
	if opts.LegacyKeys != nil {
		keys, loadErr = opts.LegacyKeys()
	}
	if len(keys) == 0 {
		err := fmt.Errorf("%w: this is a legacy (ppkencrypt/oakcryptor) file and no matching RSA key has been imported (import the old private .pem into your keyring)", ErrNoKey)
		if loadErr != nil {
			err = fmt.Errorf("%w (%w)", err, loadErr)
		}
		return nil, err
	}
	lr, err := legacy.Decrypt(src, dst, keys...)
	if errors.Is(err, legacy.ErrWrongKey) {
		return nil, fmt.Errorf("%w: %w", ErrNoKey, err)
	}
	if err != nil {
		return nil, err
	}
	res := &Result{Format: lr.Format.String(), Warnings: lr.Warnings}
	if loadErr != nil {
		res.Warnings = append(res.Warnings, loadErr.Error())
	}
	return res, nil
}

// Info is what Inspect can tell about a file without decrypting it.
type Info struct {
	Kind Kind
	// Stanzas lists the age recipient types (e.g. "mlkem768x25519",
	// "X25519", "scrypt"), each once.
	Stanzas []string
	// Recipients lists every recipient stanza in the header.
	Recipients []Stanza
	// PostQuantum is true when every recipient resists quantum attacks.
	PostQuantum bool
	// Sizes of an age file, in bytes of the binary form (an armored file
	// is larger on disk). The payload is the encrypted content.
	HeaderSize, Payload, Overhead, Total int64
	// LegacyKeyBits is the RSA key size for legacy files.
	LegacyKeyBits int
	Legacy        *legacy.Details
	// Signer is set for detached signatures.
	Signer   *sign.PublicKey
	SignedAt time.Time
}

// Stanza is one age recipient stanza: its type and first argument (for
// SSH recipients, a tag identifying the key).
type Stanza struct {
	Type, Arg string
}

// age payloads are a 16-byte nonce, then chunks of up to 64 KiB, each
// with a 16-byte tag.
const (
	ageNonce = 16
	ageChunk = 64*1024 + 16
)

// Inspect reads a file's header and walks its structure; it reads the
// whole file unless src can seek. Whether an encrypted file is signed can
// only be known after decryption.
func Inspect(src io.Reader) (*Info, error) {
	br := bufio.NewReader(src)
	prefix, _ := br.Peek(PeekSize)
	info := &Info{Kind: Detect(prefix)}
	seeker, canSeek := src.(io.ReadSeeker)
	switch info.Kind {
	case KindAge, KindAgeArmored:
		cr := &countReader{r: br}
		if info.Kind == KindAgeArmored {
			cr.r = armor.NewReader(br)
		}
		hdr, err := age.ExtractHeader(cr)
		if err != nil {
			return nil, err
		}
		info.Recipients = parseStanzas(hdr)
		info.Stanzas = parseStanzaTypes(hdr)
		info.PostQuantum = len(info.Stanzas) > 0
		for _, t := range info.Stanzas {
			if t != "mlkem768x25519" && t != "scrypt" {
				info.PostQuantum = false
			}
		}
		info.HeaderSize = int64(len(hdr))
		if canSeek && info.Kind == KindAge {
			info.Total, err = seeker.Seek(0, io.SeekEnd)
		} else {
			_, err = io.Copy(io.Discard, cr)
			info.Total = cr.n
		}
		if err != nil {
			return nil, err
		}
		if c := info.Total - info.HeaderSize - ageNonce; c > 0 {
			chunks := max(1, (c+ageChunk-1)/ageChunk)
			info.Payload = max(0, c-16*chunks)
		}
		info.Overhead = info.Total - info.Payload
	case KindLegacy:
		info.LegacyKeyBits = int(binary.BigEndian.Uint32(prefix)) * 8
		var r io.Reader = br
		if canSeek {
			if _, err := seeker.Seek(0, io.SeekStart); err != nil {
				return nil, err
			}
			r = seeker
		}
		d, err := legacy.Inspect(r)
		if err != nil {
			return nil, err
		}
		info.Legacy = d
	case KindSignature:
		data, err := io.ReadAll(io.LimitReader(br, 1<<20))
		if err != nil {
			return nil, err
		}
		h, _, err := sign.ParseDetached(data)
		if err != nil {
			return nil, err
		}
		info.Signer, info.SignedAt = h.Signer, h.Created
	default:
		return info, ErrUnknownFormat
	}
	return info, nil
}

type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func parseStanzas(hdr []byte) []Stanza {
	var out []Stanza
	for line := range strings.SplitSeq(string(hdr), "\n") {
		if rest, ok := strings.CutPrefix(line, "-> "); ok {
			typ, args, _ := strings.Cut(rest, " ")
			arg, _, _ := strings.Cut(args, " ")
			out = append(out, Stanza{typ, arg})
		}
	}
	return out
}

func parseStanzaTypes(hdr []byte) []string {
	var t []string
	for line := range strings.SplitSeq(string(hdr), "\n") {
		rest, ok := strings.CutPrefix(line, "-> ")
		if !ok {
			continue
		}
		typ, _, _ := strings.Cut(rest, " ")
		if !slices.Contains(t, typ) {
			t = append(t, typ)
		}
	}
	return t
}

var stanzaDescriptions = map[string]string{
	"mlkem768x25519": "post-quantum key (ML-KEM-768 + X25519)",
	"X25519":         "classic key (X25519)",
	"scrypt":         "passphrase",
	"ssh-ed25519":    "SSH Ed25519 key",
	"ssh-rsa":        "SSH RSA key",
}

// DescribeStanza explains an age recipient type for people.
func DescribeStanza(s string) string {
	if d, ok := stanzaDescriptions[s]; ok {
		return d
	}
	return s
}
