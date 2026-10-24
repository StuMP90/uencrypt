// Package inspect describes a file for people and scripts: how it is
// encrypted, who can open it, its sizes, and (optionally, by decrypting in
// memory) what it holds. Nothing is ever written.
package inspect

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/StuMP90/uencrypt/internal/content"
	"github.com/StuMP90/uencrypt/internal/envelope"
	"github.com/StuMP90/uencrypt/internal/keys"
	"github.com/StuMP90/uencrypt/internal/legacy"
	"github.com/StuMP90/uencrypt/internal/sign"
)

// Options controls File.
type Options struct {
	// Keyring names contacts, own keys and legacy keys (may be nil).
	Keyring *keys.Keyring
	// SSHKeys are extra SSH private keys to match SSH recipients against.
	SSHKeys []string
	// Contents decrypts the file in memory to report what it holds.
	Contents bool
	// Decrypt holds the keys and passphrase used when Contents is set.
	Decrypt envelope.DecryptOptions
}

// Report describes one file.
type Report struct {
	Path     string `json:"path"`
	Name     string `json:"name"`
	FileSize int64  `json:"fileSize"`
	// Kind is "age", "legacy", "signature" or "plain".
	Kind string `json:"kind"`
	// Format is the precise format: "age", "age (armored)",
	// "legacy-original", "legacy-chunked", "uencrypt signature", or the
	// content type of a plain file.
	Format     string      `json:"format"`
	Armored    bool        `json:"armored,omitempty"`
	Encryption string      `json:"encryption,omitempty"`
	Recipients []Recipient `json:"recipients,omitempty"`
	// PostQuantum is true when every recipient resists quantum attacks.
	PostQuantum bool `json:"postQuantum"`
	// Access says whether this computer can open the file, as far as can
	// be told without trying.
	Access string  `json:"access,omitempty"`
	Sizes  *Sizes  `json:"sizes,omitempty"`
	Legacy *Legacy `json:"legacy,omitempty"`
	// Signature is set for detached signatures and, after decrypting,
	// for signed encrypted files.
	Signature *Signature `json:"signature,omitempty"`
	// Signed is known only after decrypting (Contents).
	Signed *bool `json:"signed,omitempty"`
	// Content is what the file (decrypted, for encrypted files) holds.
	Content *content.Report `json:"content,omitempty"`
	// ContentsError explains why Contents could not decrypt the file.
	ContentsError string   `json:"contentsError,omitempty"`
	Warnings      []string `json:"warnings,omitempty"`
}

// Recipient is a group of age recipient stanzas of one type.
type Recipient struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Count       int    `json:"count"`
	// Keys names the recipients that could be identified (SSH keys).
	Keys []string `json:"keys,omitempty"`
	// Unidentified counts recipients whose key cannot be named.
	Unidentified int `json:"unidentified,omitempty"`
}

// Sizes are in bytes. For an armored file they are of the binary form.
// Overhead is everything but the payload, the header included; the payload
// of a signed file includes its signature.
type Sizes struct {
	Header   int64 `json:"header"`
	Payload  int64 `json:"payload"`
	Overhead int64 `json:"overhead"`
	Total    int64 `json:"total"`
}

// Legacy describes a ppkencrypt/oakcryptor file.
type Legacy struct {
	KeyBits   int   `json:"keyBits"`
	Chunks    int   `json:"chunks,omitempty"`
	ChunkSize int64 `json:"chunkSize,omitempty"`
	Truncated bool  `json:"truncated,omitempty"`
	// Key is the imported legacy key that opens the file, if any.
	Key string `json:"key,omitempty"`
}

// Signature names a signer.
type Signature struct {
	Fingerprint string    `json:"fingerprint"`
	Name        string    `json:"name,omitempty"`
	Own         bool      `json:"own,omitempty"`
	Known       bool      `json:"known"`
	SignedAt    time.Time `json:"signedAt,omitzero"`
}

// Describe names the signer for people.
func (s *Signature) Describe() string {
	switch {
	case s.Own:
		return fmt.Sprintf("%s [own key] (%s)", s.Name, s.Fingerprint)
	case s.Known:
		return fmt.Sprintf("%s (%s)", s.Name, s.Fingerprint)
	}
	return "unknown key " + s.Fingerprint
}

const (
	ageCipher       = "age v1: a random file key, wrapped for each recipient; content in ChaCha20-Poly1305 64 KiB chunks"
	tamperCaveat    = "the end of a legacy chunked file is not authenticated: whole trailing chunks could be removed without detection"
	truncatedCaveat = "the file looks like a legacy chunked file whose end is missing"
)

// File inspects the file at path.
func File(ctx context.Context, path string, opts Options) (*Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	rep := &Report{Path: path, Name: filepath.Base(path), FileSize: st.Size()}
	info, err := envelope.Inspect(f)
	if errors.Is(err, envelope.ErrUnknownFormat) {
		return rep, plain(f, rep)
	}
	if err != nil {
		return nil, err
	}
	rep.Format = info.Kind.String()
	switch info.Kind {
	case envelope.KindAge, envelope.KindAgeArmored:
		rep.Kind, rep.Armored = "age", info.Kind == envelope.KindAgeArmored
		rep.Encryption = ageCipher
		rep.PostQuantum = info.PostQuantum
		rep.Sizes = &Sizes{info.HeaderSize, info.Payload, info.Overhead, info.Total}
		rep.Recipients, rep.Access = recipients(info.Recipients, opts)
	case envelope.KindLegacy:
		rep.Kind = "legacy"
		describeLegacy(rep, info.Legacy, opts)
	case envelope.KindSignature:
		rep.Kind = "signature"
		rep.Signature = signer(opts.Keyring, info.Signer, info.SignedAt)
		return rep, nil
	}
	if opts.Contents {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		look(ctx, f, rep, opts)
	}
	return rep, nil
}

func plain(f *os.File, rep *Report) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	c, err := content.Analyze(f)
	if err != nil {
		return err
	}
	rep.Kind, rep.Format, rep.Content = "plain", c.Type, c
	rep.Access = "not encrypted"
	return nil
}

// look decrypts into a content analyzer, keeping nothing.
func look(ctx context.Context, f *os.File, rep *Report, opts Options) {
	a := content.New()
	res, err := envelope.Decrypt(ctx, f, a, opts.Decrypt)
	c, _ := a.Close()
	if err != nil {
		rep.ContentsError = err.Error()
		return
	}
	rep.Content = c
	rep.Signed = &res.Signed
	if res.Signed {
		rep.Signature = signer(opts.Keyring, res.Signer, res.SignedAt)
	}
	for _, w := range res.Warnings {
		if w != legacy.TamperWarning { // already in the report
			rep.Warnings = append(rep.Warnings, w)
		}
	}
}

func signer(kr *keys.Keyring, pk *sign.PublicKey, at time.Time) *Signature {
	s := &Signature{Fingerprint: pk.Fingerprint(), SignedAt: at}
	if kr != nil {
		s.Name, s.Own, s.Known = kr.SignerName(pk)
	}
	return s
}

// recipients groups stanzas by type and names the keys it can: SSH tags
// are matched to known keys, and a passphrase file says so. X25519 and
// post-quantum recipients carry no key identifier, by design.
func recipients(stanzas []envelope.Stanza, opts Options) ([]Recipient, string) {
	var out []Recipient
	index := map[string]int{}
	var tags map[string]keys.KnownSSHKey
	own, ownTypes := []string{}, map[string]int{}
	for _, s := range stanzas {
		i, ok := index[s.Type]
		if !ok {
			i = len(out)
			index[s.Type] = i
			out = append(out, Recipient{Type: s.Type, Description: envelope.DescribeStanza(s.Type)})
		}
		r := &out[i]
		r.Count++
		switch s.Type {
		case "scrypt":
		case "ssh-ed25519", "ssh-rsa":
			if tags == nil {
				tags = keys.SSHTags(opts.Keyring, opts.SSHKeys)
			}
			if k, ok := tags[s.Arg]; ok {
				r.Keys = append(r.Keys, k.Description)
				if k.Own {
					own = append(own, k.Description)
				}
			} else {
				r.Unidentified++
			}
		default:
			r.Unidentified++
		}
	}
	if opts.Keyring != nil {
		names, _ := opts.Keyring.Identities()
		for _, n := range names {
			if c, err := opts.Keyring.IdentityPublic(n); err == nil {
				ownTypes[keys.StanzaType(c.Recipient)]++
			}
		}
	}
	var access string
	_, passphrase := index["scrypt"]
	switch {
	case passphrase:
		access = "needs the passphrase it was encrypted with"
	case len(own) > 0:
		access = "yes, with " + own[0]
	default:
		for _, r := range out {
			if r.Type != "ssh-ed25519" && r.Type != "ssh-rsa" && ownTypes[r.Type] > 0 {
				access = fmt.Sprintf("possibly: you have %d %s; which key a file is for is only known by trying it", ownTypes[r.Type], plural(ownTypes[r.Type], r.Description))
				break
			}
		}
		if access == "" {
			access = "no: none of your keys match"
		}
	}
	return out, access
}

func plural(n int, s string) string {
	if n == 1 {
		return s
	}
	return s + "s"
}

func describeLegacy(rep *Report, d *legacy.Details, opts Options) {
	rep.Format = d.Format.String()
	how := "the content in one AES-256-GCM block"
	if d.Format == legacy.Chunked {
		how = "the content in AES-256-GCM chunks"
	}
	rep.Encryption = fmt.Sprintf("ppkencrypt/oakcryptor: an AES-256 key wrapped with RSA-%d (PKCS#1 v1.5); %s", d.KeyBits, how)
	rep.Sizes = &Sizes{d.HeaderSize, d.Payload, d.Overhead, d.Total}
	l := &Legacy{KeyBits: d.KeyBits, Chunks: d.Chunks, ChunkSize: d.ChunkSize, Truncated: d.Truncated}
	rep.Legacy = l
	switch {
	case d.Truncated:
		rep.Warnings = append(rep.Warnings, truncatedCaveat)
	case d.Format == legacy.Chunked:
		rep.Warnings = append(rep.Warnings, tamperCaveat)
	}
	l.Key = matchLegacy(d.WrappedKey, opts)
	if l.Key != "" {
		rep.Access = "yes, with legacy key " + l.Key
	} else {
		rep.Access = "no: none of your imported legacy keys match"
	}
}

// matchLegacy names the key that unwraps the file key: an imported one,
// or one given with the decrypt options.
func matchLegacy(wrapped []byte, opts Options) string {
	if kr := opts.Keyring; kr != nil {
		names, _ := kr.LegacyNames()
		for _, n := range names {
			if k, err := kr.LegacyKey(n); err == nil && legacy.MatchKey(wrapped, []*rsa.PrivateKey{k}) == 0 {
				return n
			}
		}
	}
	if opts.Decrypt.LegacyKeys != nil {
		if ks, err := opts.Decrypt.LegacyKeys(); err == nil && legacy.MatchKey(wrapped, ks) >= 0 {
			return "(an extra key given for this run)"
		}
	}
	return ""
}
