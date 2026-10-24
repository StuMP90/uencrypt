package keys

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"filippo.io/age"
	"filippo.io/age/agessh"

	"github.com/StuMP90/uencrypt/internal/legacy"
	"github.com/StuMP90/uencrypt/internal/sign"
)

// Keyring layout:
//
//	identities/<name>.key   secret identity file (0600, optionally locked)
//	identities/<name>.pub   its contact card, readable without unlocking
//	contacts/<name>.pub     other people's contact cards
//	legacy/<name>.pem       old ppkencrypt/oakcryptor RSA keys (decrypt only)
//	default                 name of the default identity
const (
	dirIdentities = "identities"
	dirContacts   = "contacts"
	dirLegacy     = "legacy"
	fileDefault   = "default"
)

// DefaultDir returns $UENCRYPT_KEYRING, or uencrypt under the user config
// directory (~/.config/uencrypt on Linux, %AppData%\uencrypt on Windows;
// under MSIX that path is virtualized into the package's private storage).
func DefaultDir() (string, error) {
	if d := os.Getenv("UENCRYPT_KEYRING"); d != "" {
		return d, nil
	}
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "uencrypt"), nil
}

// Keyring is a directory of identities, contacts and legacy keys.
type Keyring struct {
	Dir string
}

// Open returns the keyring at dir, creating it if needed.
func Open(dir string) (*Keyring, error) {
	for _, sub := range []string{dirIdentities, dirContacts, dirLegacy} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, err
		}
	}
	return &Keyring{Dir: dir}, nil
}

func (k *Keyring) path(sub, name, ext string) string {
	return filepath.Join(k.Dir, sub, name+ext)
}

// ErrNotFound is returned when a named key does not exist.
var ErrNotFound = errors.New("not found")

// ErrExists is returned when saving would overwrite an existing key.
var ErrExists = errors.New("already exists")

// writeNew writes data to path atomically, refusing to replace an existing
// file unless force is set.
func writeNew(path string, data []byte, perm os.FileMode, force bool) error {
	if !force {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("%s %w", filepath.Base(path), ErrExists)
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(perm); err != nil && !isWindows() {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func isWindows() bool { return os.PathSeparator == '\\' }

func listNames(dir, ext string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range ents {
		if n, ok := strings.CutSuffix(e.Name(), ext); ok && !e.IsDir() && ValidateName(n) == nil {
			names = append(names, n)
		}
	}
	slices.Sort(names)
	return names, nil
}

// SaveIdentity stores an identity, locked with passphrase if non-empty.
func (k *Keyring) SaveIdentity(id *Identity, passphrase string, force bool) error {
	if err := ValidateName(id.Name); err != nil {
		return err
	}
	data := id.Marshal()
	if passphrase != "" {
		var err error
		if data, err = Lock(data, passphrase); err != nil {
			return err
		}
	}
	if err := writeNew(k.path(dirIdentities, id.Name, ".key"), data, 0o600, force); err != nil {
		return err
	}
	return writeNew(k.path(dirIdentities, id.Name, ".pub"), id.Contact().Marshal(), 0o644, true)
}

// ImportIdentity stores an existing identity file (locked or not) as name.
// For a locked file, passphrase is used to read its public key.
func (k *Keyring) ImportIdentity(name string, data []byte, passphrase string, force bool) (*Identity, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	plain := data
	if IsEncrypted(data) {
		var err error
		if plain, err = Unlock(data, passphrase); err != nil {
			return nil, err
		}
	}
	id, err := ParseIdentity(plain)
	if err != nil {
		return nil, err
	}
	id.Name = name
	if err := writeNew(k.path(dirIdentities, name, ".key"), data, 0o600, force); err != nil {
		return nil, err
	}
	return id, writeNew(k.path(dirIdentities, name, ".pub"), id.Contact().Marshal(), 0o644, true)
}

// Identities lists the names of the user's own identities.
func (k *Keyring) Identities() ([]string, error) {
	return listNames(filepath.Join(k.Dir, dirIdentities), ".key")
}

// IdentityPublic returns the public half of an identity without unlocking it.
func (k *Keyring) IdentityPublic(name string) (*Contact, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(k.path(dirIdentities, name, ".pub"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("identity %q %w", name, ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	c, err := ParseContact(data)
	if err != nil {
		return nil, err
	}
	c.Name = name
	return c, nil
}

// IdentityLocked reports whether the named identity needs a passphrase.
func (k *Keyring) IdentityLocked(name string) (bool, error) {
	data, err := k.readIdentity(name)
	if err != nil {
		return false, err
	}
	return IsEncrypted(data), nil
}

func (k *Keyring) readIdentity(name string) ([]byte, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(k.path(dirIdentities, name, ".key"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("identity %q %w", name, ErrNotFound)
	}
	return data, err
}

// IdentityFile returns the stored identity file as is (still locked if it
// is passphrase-protected), for export and backup.
func (k *Keyring) IdentityFile(name string) ([]byte, error) { return k.readIdentity(name) }

// PassphraseFunc asks for the passphrase of the named identity. Returning
// an error (for example when no terminal is available) skips that key.
type PassphraseFunc func(name string) (string, error)

// maxPassphraseAttempts bounds interactive retries for one identity.
const maxPassphraseAttempts = 3

// Unlocker opens locked identities, remembering passphrases that worked so
// several keys sharing one passphrase prompt only once.
type Unlocker struct {
	Ask PassphraseFunc

	mu    sync.Mutex
	known []string
}

func (u *Unlocker) unlock(name string, data []byte) ([]byte, error) {
	if !IsEncrypted(data) {
		return data, nil
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, p := range u.known {
		if plain, err := Unlock(data, p); err == nil {
			return plain, nil
		}
	}
	if u.Ask == nil {
		return nil, fmt.Errorf("identity %q: %w", name, ErrLocked)
	}
	for range maxPassphraseAttempts {
		p, err := u.Ask(name)
		if err != nil {
			return nil, fmt.Errorf("identity %q: %w", name, err)
		}
		plain, err := Unlock(data, p)
		if err == nil {
			u.known = append(u.known, p)
			return plain, nil
		}
		if !errors.Is(err, ErrBadPassphrase) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("identity %q: %w", name, ErrBadPassphrase)
}

// LoadIdentity reads and, if needed, unlocks a named identity.
func (k *Keyring) LoadIdentity(name string, u *Unlocker) (*Identity, error) {
	data, err := k.readIdentity(name)
	if err != nil {
		return nil, err
	}
	if u == nil {
		u = &Unlocker{}
	}
	plain, err := u.unlock(name, data)
	if err != nil {
		return nil, err
	}
	id, err := ParseIdentity(plain)
	if err != nil {
		return nil, fmt.Errorf("identity %q: %w", name, err)
	}
	id.Name = name
	return id, nil
}

// DefaultIdentity returns the name of the default identity: the one set
// with SetDefault, or the only identity if there is exactly one.
func (k *Keyring) DefaultIdentity() (string, error) {
	if b, err := os.ReadFile(filepath.Join(k.Dir, fileDefault)); err == nil {
		name := strings.TrimSpace(string(b))
		if _, err := os.Stat(k.path(dirIdentities, name, ".key")); err == nil {
			return name, nil
		}
	}
	names, err := k.Identities()
	if err != nil {
		return "", err
	}
	switch len(names) {
	case 0:
		return "", errors.New("no identities: create one with `uencrypt keys new NAME`")
	case 1:
		return names[0], nil
	}
	return "", fmt.Errorf("several identities (%s): choose one or set a default", strings.Join(names, ", "))
}

// SetDefault records the default identity.
func (k *Keyring) SetDefault(name string) error {
	if _, err := k.readIdentity(name); err != nil {
		return err
	}
	return writeNew(filepath.Join(k.Dir, fileDefault), []byte(name+"\n"), 0o644, true)
}

// AddContact stores a contact card under c.Name.
func (k *Keyring) AddContact(c *Contact, force bool) error {
	if err := ValidateName(c.Name); err != nil {
		return err
	}
	return writeNew(k.path(dirContacts, c.Name, ".pub"), c.Marshal(), 0o644, force)
}

// Contacts lists contact names.
func (k *Keyring) Contacts() ([]string, error) {
	return listNames(filepath.Join(k.Dir, dirContacts), ".pub")
}

// Contact loads a named contact.
func (k *Keyring) Contact(name string) (*Contact, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(k.path(dirContacts, name, ".pub"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("contact %q %w", name, ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	c, err := ParseContact(data)
	if err != nil {
		return nil, fmt.Errorf("contact %q: %w", name, err)
	}
	c.Name = name
	return c, nil
}

// Recipient resolves a name to a contact, falling back to the user's own
// identities so people can encrypt to themselves by name.
func (k *Keyring) Recipient(name string) (*Contact, error) {
	c, err := k.Contact(name)
	if errors.Is(err, ErrNotFound) {
		if c2, err2 := k.IdentityPublic(name); err2 == nil {
			return c2, nil
		}
	}
	return c, err
}

// ImportLegacy stores an old RSA private key for decrypting legacy files.
func (k *Keyring) ImportLegacy(name string, pemData []byte, force bool) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if _, err := legacy.ParsePrivateKey(pemData); err != nil {
		return err
	}
	return writeNew(k.path(dirLegacy, name, ".pem"), pemData, 0o600, force)
}

// LegacyNames lists imported legacy keys.
func (k *Keyring) LegacyNames() ([]string, error) {
	return listNames(filepath.Join(k.Dir, dirLegacy), ".pem")
}

// LegacyKeys loads all imported legacy keys. Unreadable keys are skipped
// and reported in the returned error alongside the keys that did load.
func (k *Keyring) LegacyKeys() ([]*rsa.PrivateKey, error) {
	names, err := k.LegacyNames()
	if err != nil {
		return nil, err
	}
	var keys []*rsa.PrivateKey
	var errs []error
	for _, n := range names {
		data, err := os.ReadFile(k.path(dirLegacy, n, ".pem"))
		if err == nil {
			var key *rsa.PrivateKey
			if key, err = legacy.ParsePrivateKey(data); err == nil {
				keys = append(keys, key)
				continue
			}
		}
		errs = append(errs, fmt.Errorf("legacy key %q: %w", n, err))
	}
	return keys, errors.Join(errs...)
}

// DetectKind says what an imported key file holds: a legacy RSA private
// key, an identity (possibly passphrase-protected), or otherwise a contact.
// It does not validate the data.
func DetectKind(data []byte) Kind {
	switch {
	case bytes.Contains(data, []byte("PRIVATE KEY-----")):
		return KindLegacy
	case IsEncrypted(data) || bytes.Contains(data, []byte("AGE-SECRET-KEY")):
		return KindIdentity
	}
	return KindContact
}

// Kind selects which part of the keyring Remove deletes from.
type Kind int

const (
	KindIdentity Kind = iota
	KindContact
	KindLegacy
)

// Remove deletes a named identity, contact or legacy key.
func (k *Keyring) Remove(kind Kind, name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	var paths []string
	switch kind {
	case KindIdentity:
		paths = []string{k.path(dirIdentities, name, ".key"), k.path(dirIdentities, name, ".pub")}
	case KindContact:
		paths = []string{k.path(dirContacts, name, ".pub")}
	case KindLegacy:
		paths = []string{k.path(dirLegacy, name, ".pem")}
	}
	if _, err := os.Stat(paths[0]); errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%q %w", name, ErrNotFound)
	}
	for _, p := range paths {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// SignerName looks up who owns a signing key: a contact name, or an own
// identity name (with own set). ok is false for an unknown signer.
func (k *Keyring) SignerName(pk *sign.PublicKey) (name string, own, ok bool) {
	if names, err := k.Identities(); err == nil {
		for _, n := range names {
			if c, err := k.IdentityPublic(n); err == nil && pk.Equal(c.Signer) {
				return n, true, true
			}
		}
	}
	if names, err := k.Contacts(); err == nil {
		for _, n := range names {
			if c, err := k.Contact(n); err == nil && pk.Equal(c.Signer) {
				return n, false, true
			}
		}
	}
	return "", false, false
}

// DecryptionIdentities returns age identities for every identity in the
// keyring. They are lazy: a key is only read and unlocked when a file has
// a stanza of its type, so locked keys don't prompt needlessly.
func (k *Keyring) DecryptionIdentities(u *Unlocker) ([]age.Identity, error) {
	names, err := k.Identities()
	if err != nil {
		return nil, err
	}
	ids := make([]age.Identity, 0, len(names))
	for _, n := range names {
		stanza := ""
		if c, err := k.IdentityPublic(n); err == nil {
			stanza = StanzaType(c.Recipient)
		}
		ids = append(ids, &lazyIdentity{load: func() (age.Identity, error) {
			id, err := k.LoadIdentity(n, u)
			if err != nil {
				return nil, err
			}
			return id.Age, nil
		}, stanza: stanza})
	}
	return ids, nil
}

// StanzaType returns the age header stanza type a recipient produces.
func StanzaType(r age.Recipient) string {
	switch r.(type) {
	case *age.HybridRecipient:
		return "mlkem768x25519"
	case *age.X25519Recipient:
		return "X25519"
	case *agessh.Ed25519Recipient:
		return "ssh-ed25519"
	case *agessh.RSARecipient:
		return "ssh-rsa"
	}
	return ""
}

// LazyIdentity wraps a loader as an age.Identity that loads on first use,
// and only when the file has a stanza of the given type ("" matches any).
// Use it for identity files given on the command line.
func LazyIdentity(stanza string, load func() (age.Identity, error)) age.Identity {
	return &lazyIdentity{stanza: stanza, load: load}
}

type lazyIdentity struct {
	stanza string
	load   func() (age.Identity, error)

	once sync.Once
	id   age.Identity
	err  error
}

func (l *lazyIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if l.stanza != "" && !slices.ContainsFunc(stanzas, func(s *age.Stanza) bool { return s.Type == l.stanza }) {
		return nil, age.ErrIncorrectIdentity
	}
	l.once.Do(func() { l.id, l.err = l.load() })
	if l.err != nil {
		// Wrapping ErrIncorrectIdentity lets age move on to other keys; the
		// reason still appears in NoIdentityMatchError.Errors.
		return nil, fmt.Errorf("%w: %w", age.ErrIncorrectIdentity, l.err)
	}
	return l.id.Unwrap(stanzas)
}

// LegacyKey loads one imported legacy key.
func (k *Keyring) LegacyKey(name string) (*rsa.PrivateKey, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(k.path(dirLegacy, name, ".pem"))
	if err != nil {
		return nil, err
	}
	return legacy.ParsePrivateKey(data)
}
