package keys

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SSHTag is the short key tag age puts in an SSH recipient stanza (the
// first four bytes of the SHA-256 of the key), so a file's SSH recipients
// can be matched to known keys without decrypting.
func SSHTag(pub ssh.PublicKey) string {
	h := sha256.Sum256(pub.Marshal())
	return base64.RawStdEncoding.EncodeToString(h[:4])
}

// KnownSSHKey is an SSH public key a stanza tag can be matched to.
type KnownSSHKey struct {
	// Description names the key: "contact alice" or "~/.ssh/id_ed25519".
	Description string
	// Own is true when the private key is available to decrypt.
	Own bool
}

// SSHTags maps stanza tags to the SSH keys known here: the standard keys
// in ~/.ssh (and any other .pub files there), the extra private keys
// given, and SSH contacts in the keyring (kr may be nil).
func SSHTags(kr *Keyring, extra []string) map[string]KnownSSHKey {
	tags := map[string]KnownSSHKey{}
	add := func(line []byte, k KnownSSHKey) {
		if pub, _, _, _, err := ssh.ParseAuthorizedKey(line); err == nil {
			if old, ok := tags[SSHTag(pub)]; !ok || (k.Own && !old.Own) {
				tags[SSHTag(pub)] = k
			}
		}
	}
	addPrivate := func(path, desc string) bool {
		if b, err := os.ReadFile(path + ".pub"); err == nil {
			add(b, KnownSSHKey{desc, true})
			return true
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return false
		}
		pub, err := sshPublicFromPrivate(data)
		if err != nil {
			return false
		}
		tags[SSHTag(pub)] = KnownSSHKey{desc, true}
		return true
	}
	if home, err := os.UserHomeDir(); err == nil {
		dir := filepath.Join(home, ".ssh")
		pubs, _ := filepath.Glob(filepath.Join(dir, "*.pub"))
		for _, p := range pubs {
			priv := strings.TrimSuffix(p, ".pub")
			desc := "~/.ssh/" + filepath.Base(priv)
			if st, err := os.Stat(priv); err == nil && st.Mode().IsRegular() {
				addPrivate(priv, desc)
			} else if b, err := os.ReadFile(p); err == nil {
				add(b, KnownSSHKey{"~/.ssh/" + filepath.Base(p), false})
			}
		}
		for _, k := range DefaultSSHKeys {
			addPrivate(filepath.Join(dir, k.File), "~/.ssh/"+k.File)
		}
	}
	for _, p := range extra {
		addPrivate(p, p)
	}
	if kr != nil {
		names, _ := kr.Contacts()
		for _, n := range names {
			if c, err := kr.Contact(n); err == nil && IsSSHRecipient(c.RecipientString) {
				add([]byte(c.RecipientString), KnownSSHKey{"contact " + n, false})
			}
		}
	}
	return tags
}

// sshPublicFromPrivate gets the public key from a private key file,
// including a passphrase-protected one in the OpenSSH format.
func sshPublicFromPrivate(data []byte) (ssh.PublicKey, error) {
	s, err := ssh.ParsePrivateKey(data)
	if err == nil {
		return s.PublicKey(), nil
	}
	if missing, ok := err.(*ssh.PassphraseMissingError); ok && missing.PublicKey != nil {
		return missing.PublicKey, nil
	}
	return nil, err
}
