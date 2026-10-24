package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// sshKey writes a private key (optionally passphrase-protected) and its
// .pub file, returning the private key path and the authorized_keys line.
func sshKey(t *testing.T, key crypto.Signer, pass string) (string, string) {
	t.Helper()
	var block *pem.Block
	var err error
	if pass == "" {
		block, err = ssh.MarshalPrivateKey(key, "alice@laptop")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(key, "alice@laptop", []byte(pass))
	}
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " alice@laptop"
	path := filepath.Join(t.TempDir(), "id")
	os.WriteFile(path, pem.EncodeToMemory(block), 0o600)
	os.WriteFile(path+".pub", []byte(line+"\n"), 0o644)
	return path, line
}

func TestSSHKeys(t *testing.T) {
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	for _, tc := range []struct {
		name   string
		key    crypto.Signer
		stanza string
	}{{"ed25519", edKey, "ssh-ed25519"}, {"rsa", rsaKey, "ssh-rsa"}} {
		t.Run(tc.name, func(t *testing.T) {
			path, line := sshKey(t, tc.key, "")
			c, err := ParseContact([]byte(line + "\n"))
			if err != nil {
				t.Fatal(err)
			}
			if c.Name != "alice-laptop" || strings.Contains(c.RecipientString, "alice") || StanzaType(c.Recipient) != tc.stanza {
				t.Fatalf("contact: name %q, key %q, stanza %q", c.Name, c.RecipientString, StanzaType(c.Recipient))
			}
			// The saved card parses back to the same key.
			c2, err := ParseContact(c.Marshal())
			if err != nil || c2.RecipientString != c.RecipientString || c2.Name != c.Name {
				t.Fatalf("re-parse: %v %+v", err, c2)
			}
			id, err := LoadSSHIdentity(path, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := roundTrip(t, c.Recipient, id); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSSHEncryptedKey(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	path, line := sshKey(t, key, "hunter2")
	r, err := ParseRecipient(line)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSSHIdentity(path, nil); !errors.Is(err, ErrLocked) {
		t.Fatalf("no prompt: want ErrLocked, got %v", err)
	}

	var asked []bool
	answers := []string{"wrong", "hunter2"}
	id, err := LoadSSHIdentity(path, func(p string, retry bool) (string, error) {
		asked = append(asked, retry)
		a := answers[0]
		answers = answers[1:]
		return a, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// A file for someone else does not ask for the passphrase.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	_, otherLine := sshKey(t, other, "")
	or, _ := ParseRecipient(otherLine)
	if err := roundTrip(t, or, id); err == nil || len(asked) != 0 {
		t.Fatalf("other recipient: err %v, asked %v", err, asked)
	}
	if err := roundTrip(t, r, id); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 2 || asked[0] || !asked[1] {
		t.Fatalf("prompts: %v", asked)
	}

	// A cancelled prompt comes back as itself.
	cancel := errors.New("cancelled")
	id, _ = LoadSSHIdentity(path, func(string, bool) (string, error) { return "", cancel })
	if err := roundTrip(t, r, id); !errors.Is(err, cancel) {
		t.Fatalf("want cancel, got %v", err)
	}
}

func TestSSHUnsupported(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := ssh.NewPublicKey(k.Public())
	if _, err := ParseRecipient(string(ssh.MarshalAuthorizedKey(pub))); err == nil ||
		!strings.Contains(err.Error(), "unsupported SSH key type") {
		t.Fatalf("ecdsa: %v", err)
	}
	block, _ := ssh.MarshalPrivateKey(k, "")
	if !IsSSHPrivateKey(pem.EncodeToMemory(block)) {
		t.Fatal("not detected as an SSH private key")
	}
}

func TestSplitRecipients(t *testing.T) {
	got := SplitRecipients("age1abc, ssh-ed25519 AAAAkey alice@laptop\nssh-rsa AAAArsa my work key age1pq1def;age1x")
	want := []string{"age1abc", "ssh-ed25519 AAAAkey", "ssh-rsa AAAArsa", "age1pq1def", "age1x"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q", got)
	}
}

func TestParseRecipientsFile(t *testing.T) {
	_, a, _ := ed25519.GenerateKey(rand.Reader)
	_, line := sshKey(t, a, "")
	id, _ := NewIdentity("bob", false)
	rs, err := ParseRecipientsFile([]byte("# team\n" + line + "\n\n" + string(id.Contact().Marshal())))
	if err != nil || len(rs) != 2 {
		t.Fatalf("%v, %d recipients", err, len(rs))
	}
	if _, err := ParseRecipientsFile([]byte("# nothing\n")); err == nil {
		t.Fatal("empty file accepted")
	}
}
