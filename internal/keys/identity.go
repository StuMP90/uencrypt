// Package keys handles uencrypt identities (secret keys), contacts (public
// keys) and the on-disk keyring.
//
// Both file types are deliberately standard age files with extra metadata
// in comments, so the stock age tools can use them directly:
//
//	age -d -i stuart.key backup.tar.age   # identity file
//	age -R alice.pub -o out.age in.tar     # contact card
package keys

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/StuMP90/uencrypt/internal/sign"
)

const (
	metaName      = "name"
	metaCreated   = "created"
	metaRecipient = "public key"
	metaSignFP    = "signing fingerprint"
	metaSigner    = "uencrypt-signer"
	metaSignKey   = "uencrypt-signing-key"
)

// Identity is a user's own key pair: an age identity for decryption and,
// for keys made by uencrypt, a hybrid signing key.
type Identity struct {
	Name    string
	Created time.Time
	Age     age.Identity
	// Recipient is the public age recipient string for Age.
	Recipient string
	// Signer may be nil for plain age identities imported from elsewhere.
	Signer *sign.SecretKey
}

// NewIdentity generates a key pair. By default the age key is the
// post-quantum hybrid (ML-KEM-768 + X25519); classic selects plain X25519
// for recipients whose age tools predate v1.3.
func NewIdentity(name string, classic bool) (*Identity, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	id := &Identity{Name: name, Created: time.Now().UTC().Truncate(time.Second)}
	if classic {
		k, err := age.GenerateX25519Identity()
		if err != nil {
			return nil, err
		}
		id.Age, id.Recipient = k, k.Recipient().String()
	} else {
		k, err := age.GenerateHybridIdentity()
		if err != nil {
			return nil, err
		}
		id.Age, id.Recipient = k, k.Recipient().String()
	}
	s, err := sign.Generate()
	if err != nil {
		return nil, err
	}
	id.Signer = s
	return id, nil
}

func ageSecret(i age.Identity) string {
	switch k := i.(type) {
	case *age.HybridIdentity:
		return k.String()
	case *age.X25519Identity:
		return k.String()
	}
	return ""
}

// Marshal encodes the identity as an unencrypted age identity file.
func (id *Identity) Marshal() []byte {
	var b bytes.Buffer
	b.WriteString("# uencrypt identity - KEEP THIS FILE SECRET.\n")
	b.WriteString("# This is a standard age identity file: `age -d -i <this file>` works.\n")
	writeMeta(&b, metaName, id.Name)
	writeMeta(&b, metaCreated, id.Created.UTC().Format(time.RFC3339))
	writeMeta(&b, metaRecipient, id.Recipient)
	if id.Signer != nil {
		writeMeta(&b, metaSignFP, id.Signer.Public().Fingerprint())
		writeMeta(&b, metaSignKey, id.Signer.String())
	}
	b.WriteString(ageSecret(id.Age) + "\n")
	return b.Bytes()
}

// Contact returns the shareable public half of the identity.
func (id *Identity) Contact() *Contact {
	c := &Contact{Name: id.Name, Created: id.Created, RecipientString: id.Recipient}
	c.Recipient, _ = parseRecipient(id.Recipient)
	if id.Signer != nil {
		c.Signer = id.Signer.Public()
	}
	return c
}

// IsPostQuantum reports whether the identity's encryption key is the hybrid
// ML-KEM type.
func (id *Identity) IsPostQuantum() bool {
	_, ok := id.Age.(*age.HybridIdentity)
	return ok
}

// ParseIdentity parses an unencrypted identity file. Plain age identity
// files (from age-keygen) are accepted and simply have no signing key.
func ParseIdentity(data []byte) (*Identity, error) {
	if IsEncrypted(data) {
		return nil, ErrLocked
	}
	ids, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if len(ids) != 1 {
		return nil, fmt.Errorf("identity file must contain exactly one key, found %d", len(ids))
	}
	id := &Identity{Age: ids[0]}
	switch k := ids[0].(type) {
	case *age.HybridIdentity:
		id.Recipient = k.Recipient().String()
	case *age.X25519Identity:
		id.Recipient = k.Recipient().String()
	default:
		return nil, errors.New("unsupported identity type")
	}
	meta := readMeta(data)
	id.Name = meta[metaName]
	id.Created, _ = time.Parse(time.RFC3339, meta[metaCreated])
	if s := meta[metaSignKey]; s != "" {
		if id.Signer, err = sign.ParseSecretKey(s); err != nil {
			return nil, err
		}
	}
	return id, nil
}

// ErrLocked means an identity file is passphrase-protected.
var ErrLocked = errors.New("identity file is passphrase-protected")

// IsEncrypted reports whether data is a passphrase-protected (age scrypt
// encrypted) identity file.
func IsEncrypted(data []byte) bool {
	t := bytes.TrimLeft(data, " \t\r\n")
	return bytes.HasPrefix(t, []byte(armor.Header)) || bytes.HasPrefix(t, []byte("age-encryption.org/"))
}

// Lock encrypts an identity file with a passphrase. The result is an armored
// age file, which the age CLI also accepts as an identity file.
func Lock(plain []byte, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("empty passphrase")
	}
	r, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	aw := armor.NewWriter(&b)
	w, err := age.Encrypt(aw, r)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plain); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if err := aw.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// ErrBadPassphrase is returned by Unlock for a wrong passphrase.
var ErrBadPassphrase = errors.New("incorrect passphrase")

// Unlock decrypts a passphrase-protected identity file.
func Unlock(data []byte, passphrase string) ([]byte, error) {
	id, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, err
	}
	var src io.Reader = bytes.NewReader(data)
	if bytes.HasPrefix(bytes.TrimLeft(data, " \t\r\n"), []byte(armor.Header)) {
		src = armor.NewReader(src)
	}
	r, err := age.Decrypt(src, id)
	if err != nil {
		var nm *age.NoIdentityMatchError
		if errors.As(err, &nm) {
			return nil, ErrBadPassphrase
		}
		return nil, err
	}
	return io.ReadAll(io.LimitReader(r, 1<<20))
}

// Contact is someone's public key: who you can encrypt to and whose
// signatures you can verify.
type Contact struct {
	Name            string
	Created         time.Time
	Recipient       age.Recipient
	RecipientString string
	// Signer may be nil for plain age recipients.
	Signer *sign.PublicKey
}

// Marshal encodes the contact as an age recipients file.
func (c *Contact) Marshal() []byte {
	var b bytes.Buffer
	b.WriteString("# uencrypt public key - safe to share.\n")
	b.WriteString("# This is a standard age recipients file: `age -R <this file>` works.\n")
	writeMeta(&b, metaName, c.Name)
	if !c.Created.IsZero() {
		writeMeta(&b, metaCreated, c.Created.UTC().Format(time.RFC3339))
	}
	if c.Signer != nil {
		writeMeta(&b, metaSignFP, c.Signer.Fingerprint())
		writeMeta(&b, metaSigner, c.Signer.String())
	}
	b.WriteString(c.RecipientString + "\n")
	return b.Bytes()
}

// IsPostQuantum reports whether files encrypted to this contact are
// protected against quantum attacks.
func (c *Contact) IsPostQuantum() bool {
	_, ok := c.Recipient.(*age.HybridRecipient)
	return ok
}

// ParseContact parses a contact card, or a bare age recipient string.
func ParseContact(data []byte) (*Contact, error) {
	var recips []string
	sc := bufio.NewScanner(io.LimitReader(bytes.NewReader(data), 1<<20))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			recips = append(recips, line)
		}
	}
	if len(recips) != 1 {
		return nil, fmt.Errorf("public key file must contain exactly one recipient, found %d", len(recips))
	}
	meta := readMeta(data)
	c := &Contact{Name: meta[metaName], RecipientString: recips[0]}
	if IsSSHRecipient(recips[0]) {
		// Keep the key without its comment; the comment ("alice@laptop")
		// stands in for a missing name.
		var comment string
		var err error
		if c.Recipient, c.RecipientString, comment, err = parseSSHRecipient(recips[0]); err != nil {
			return nil, err
		}
		if c.Name == "" {
			c.Name = nameFromComment(comment)
		}
	} else {
		var err error
		if c.Recipient, err = parseRecipient(recips[0]); err != nil {
			return nil, err
		}
	}
	c.Created, _ = time.Parse(time.RFC3339, meta[metaCreated])
	if s := meta[metaSigner]; s != "" {
		var err error
		if c.Signer, err = sign.ParsePublicKey(s); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func parseRecipient(s string) (age.Recipient, error) {
	switch {
	case strings.HasPrefix(s, "age1pq1"):
		return age.ParseHybridRecipient(s)
	case strings.HasPrefix(s, "age1"):
		return age.ParseX25519Recipient(s)
	case IsSSHRecipient(s):
		r, _, _, err := parseSSHRecipient(s)
		return r, err
	}
	return nil, fmt.Errorf("unsupported recipient %q (expected age1..., age1pq1... or an ssh-ed25519/ssh-rsa key)", truncate(s, 20))
}

// ParseRecipient parses an age1... or age1pq1... recipient string, or an
// ssh-ed25519 or ssh-rsa public key (with or without its comment).
func ParseRecipient(s string) (age.Recipient, error) { return parseRecipient(strings.TrimSpace(s)) }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func writeMeta(b *bytes.Buffer, k, v string) {
	v = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, v)
	fmt.Fprintf(b, "# %s: %s\n", k, v)
}

func readMeta(data []byte) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		line, ok := strings.CutPrefix(sc.Text(), "# ")
		if !ok {
			continue
		}
		if k, v, ok := strings.Cut(line, ": "); ok {
			if _, dup := m[k]; !dup {
				m[k] = strings.TrimSpace(v)
			}
		}
	}
	return m
}

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidateName checks a key or contact name is safe to use as a file name.
func ValidateName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("invalid name %q: use 1-64 letters, digits, '.', '_' or '-'", name)
	}
	return nil
}
