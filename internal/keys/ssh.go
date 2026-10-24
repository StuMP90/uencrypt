package keys

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"
)

// SSH keys work as age supports them: ssh-ed25519 and ssh-rsa public keys
// are classic (not post-quantum) recipients, and the matching private keys
// decrypt. They cannot sign. Private SSH keys stay where they are (usually
// ~/.ssh); they are never copied into the keyring.

// ErrSSHPrivateKey is returned when an SSH private key is imported.
var ErrSSHPrivateKey = errors.New("this is an SSH private key: import its .pub file as a contact instead; " +
	"files encrypted to it are decrypted with the private key where it is")

// IsSSHPrivateKey reports whether data is an OpenSSH private key file.
func IsSSHPrivateKey(data []byte) bool {
	return bytes.Contains(data, []byte("-----BEGIN OPENSSH PRIVATE KEY-----"))
}

// IsSSHRecipient reports whether s looks like an SSH public key line,
// including types age does not support (so they get a clear error).
func IsSSHRecipient(s string) bool {
	s = strings.TrimSpace(s)
	for _, p := range []string{"ssh-", "ecdsa-sha2-", "sk-ssh-", "sk-ecdsa-"} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// parseSSHRecipient parses an authorized_keys style line and returns the
// recipient, the key without its comment, and the comment.
func parseSSHRecipient(s string) (age.Recipient, string, string, error) {
	pk, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(s))
	if err != nil {
		return nil, "", "", fmt.Errorf("malformed SSH public key %q: %w", truncate(s, 30), err)
	}
	if t := pk.Type(); t != ssh.KeyAlgoED25519 && t != ssh.KeyAlgoRSA {
		return nil, "", "", fmt.Errorf("unsupported SSH key type %s (age supports ssh-ed25519 and ssh-rsa)", t)
	}
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
	r, err := agessh.ParseRecipient(key)
	if err != nil {
		return nil, "", "", err
	}
	return r, key, comment, nil
}

var badNameChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// nameFromComment turns an SSH key comment such as "alice@laptop" into a
// keyring name ("alice-laptop"), or "" if nothing usable is left.
func nameFromComment(c string) string {
	n := strings.Trim(badNameChars.ReplaceAllString(strings.TrimSpace(c), "-"), "-._")
	if len(n) > 64 {
		n = n[:64]
	}
	if ValidateName(n) != nil {
		return ""
	}
	return n
}

// SSHPassphraseFunc asks for the passphrase of the SSH key at path; retry
// is true after a wrong one.
type SSHPassphraseFunc func(path string, retry bool) (string, error)

// LoadSSHIdentity reads an SSH private key file for decrypting. For a
// passphrase-protected key, ask is called only when a file is actually
// encrypted to it, and again (up to three times) after a wrong passphrase.
// The public key comes from the private key file, or from path+".pub" for
// old-style keys that do not include it.
func LoadSSHIdentity(path string, ask SSHPassphraseFunc) (age.Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseSSHIdentity(data, path, ask)
}

// ParseSSHIdentity is LoadSSHIdentity for key data already read from path.
func ParseSSHIdentity(data []byte, path string, ask SSHPassphraseFunc) (age.Identity, error) {
	id, err := agessh.ParseIdentity(data)
	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
		}
		return id, nil
	}
	pub := missing.PublicKey
	if pub == nil {
		b, err := os.ReadFile(path + ".pub")
		if err != nil {
			return nil, fmt.Errorf("%s is passphrase-protected and its public key %s.pub could not be read: %w",
				filepath.Base(path), filepath.Base(path), err)
		}
		if pub, _, _, _, err = ssh.ParseAuthorizedKey(b); err != nil {
			return nil, fmt.Errorf("%s.pub: %w", filepath.Base(path), err)
		}
	}
	if ask == nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), ErrLocked)
	}
	e := &encryptedSSH{path: path}
	e.id, err = agessh.NewEncryptedSSHIdentity(pub, data, func() ([]byte, error) {
		for i := range maxPassphraseAttempts {
			p, err := ask(path, i > 0)
			if err != nil {
				e.askErr = err
				return nil, err
			}
			if _, err := ssh.ParseRawPrivateKeyWithPassphrase(data, []byte(p)); err == nil {
				return []byte(p), nil
			}
		}
		e.askErr = fmt.Errorf("SSH key %s: %w", filepath.Base(path), ErrBadPassphrase)
		return nil, e.askErr
	})
	if err != nil {
		return nil, err
	}
	return e, nil
}

// encryptedSSH keeps the prompt's own error (such as a cancel), which
// agessh would otherwise flatten into a string.
type encryptedSSH struct {
	path   string
	id     *agessh.EncryptedSSHIdentity
	askErr error
}

func (e *encryptedSSH) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	e.askErr = nil
	k, err := e.id.Unwrap(stanzas)
	if err != nil && e.askErr != nil {
		return nil, e.askErr
	}
	return k, err
}

// DefaultSSHKeys are the private keys age-compatible tools look for, in
// ~/.ssh, with the stanza type each produces.
var DefaultSSHKeys = []struct{ File, Stanza string }{
	{"id_ed25519", "ssh-ed25519"},
	{"id_rsa", "ssh-rsa"},
}

// DefaultSSHIdentities returns the user's standard SSH keys that exist, as
// identities that read the key only when a file has a stanza of its type.
func DefaultSSHIdentities(ask SSHPassphraseFunc) []age.Identity {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	var ids []age.Identity
	for _, k := range DefaultSSHKeys {
		path := filepath.Join(home, ".ssh", k.File)
		if st, err := os.Stat(path); err != nil || !st.Mode().IsRegular() {
			continue
		}
		ids = append(ids, LazyIdentity(k.Stanza, func() (age.Identity, error) { return LoadSSHIdentity(path, ask) }))
	}
	return ids
}

// SplitRecipients splits text holding several public keys, separated by
// spaces, commas or new lines, into one string per key. An SSH key keeps
// its key data and drops its comment, which runs up to the next key.
func SplitRecipients(text string) []string {
	var out []string
	fields := strings.FieldsFunc(text, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		if !IsSSHRecipient(f) {
			out = append(out, f)
			continue
		}
		if i+1 < len(fields) {
			i++
			f += " " + fields[i]
		}
		for i+1 < len(fields) && !strings.HasPrefix(fields[i+1], "age1") && !IsSSHRecipient(fields[i+1]) {
			i++
		}
		out = append(out, f)
	}
	return out
}

// ParseRecipientsFile parses a recipients file as age -R reads it: one
// age1..., age1pq1... or SSH public key per line, with blank lines and
// # comments ignored. Contact cards and authorized_keys files qualify.
func ParseRecipientsFile(data []byte) ([]age.Recipient, error) {
	var out []age.Recipient
	for n, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		r, err := ParseRecipient(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n+1, err)
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, errors.New("no recipients found")
	}
	return out, nil
}
