package keys

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func roundTrip(t *testing.T, r age.Recipient, ids ...age.Identity) error {
	t.Helper()
	var b bytes.Buffer
	w, err := age.Encrypt(&b, r)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, "secret")
	w.Close()
	d, err := age.Decrypt(&b, ids...)
	if err != nil {
		return err
	}
	got, _ := io.ReadAll(d)
	if string(got) != "secret" {
		t.Fatalf("got %q", got)
	}
	return nil
}

func TestIdentityRoundTrip(t *testing.T) {
	for _, classic := range []bool{false, true} {
		id, err := NewIdentity("alice", classic)
		if err != nil {
			t.Fatal(err)
		}
		if id.IsPostQuantum() == classic {
			t.Fatal("wrong key type")
		}
		id2, err := ParseIdentity(id.Marshal())
		if err != nil {
			t.Fatal(err)
		}
		if id2.Name != "alice" || id2.Recipient != id.Recipient || !id2.Signer.Public().Equal(id.Signer.Public()) || !id2.Created.Equal(id.Created) {
			t.Fatalf("identity changed: %+v", id2)
		}
		// The file must still be a plain age identity file.
		ids, err := age.ParseIdentities(bytes.NewReader(id.Marshal()))
		if err != nil || len(ids) != 1 {
			t.Fatalf("age.ParseIdentities: %v", err)
		}
		c, err := ParseContact(id.Contact().Marshal())
		if err != nil {
			t.Fatal(err)
		}
		if c.Name != "alice" || !c.Signer.Equal(id.Signer.Public()) || c.IsPostQuantum() == classic {
			t.Fatalf("contact changed: %+v", c)
		}
		rs, err := age.ParseRecipients(bytes.NewReader(id.Contact().Marshal()))
		if err != nil || len(rs) != 1 {
			t.Fatalf("age.ParseRecipients: %v", err)
		}
		if err := roundTrip(t, c.Recipient, id2.Age); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPlainAgeFiles(t *testing.T) {
	k, _ := age.GenerateHybridIdentity()
	id, err := ParseIdentity([]byte("# created by age-keygen\n" + k.String() + "\n"))
	if err != nil || id.Signer != nil || id.Recipient != k.Recipient().String() {
		t.Fatalf("plain identity: %v", err)
	}
	c, err := ParseContact([]byte(k.Recipient().String()))
	if err != nil || c.Signer != nil {
		t.Fatalf("bare recipient: %v", err)
	}
	if _, err := ParseContact([]byte("ssh-ed25519 AAAA")); err == nil {
		t.Fatal("malformed ssh key accepted")
	}
}

func TestLockUnlock(t *testing.T) {
	id, _ := NewIdentity("bob", false)
	locked, err := Lock(id.Marshal(), "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !IsEncrypted(locked) {
		t.Fatal("not detected as locked")
	}
	if _, err := ParseIdentity(locked); !errors.Is(err, ErrLocked) {
		t.Fatalf("want ErrLocked, got %v", err)
	}
	if _, err := Unlock(locked, "wrong"); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("want ErrBadPassphrase, got %v", err)
	}
	plain, err := Unlock(locked, "correct horse")
	if err != nil || !bytes.Equal(plain, id.Marshal()) {
		t.Fatalf("unlock: %v", err)
	}
}

func TestNames(t *testing.T) {
	for _, ok := range []string{"a", "alice", "Backup-Server_2.key", "x1234567890123456789012345678901234567890123456789012345678901"} {
		if ValidateName(ok) != nil {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", ".hidden", "../x", "a/b", `a\b`, "a b", "-x", "é"} {
		if ValidateName(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestKeyring(t *testing.T) {
	kr, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kr.DefaultIdentity(); err == nil {
		t.Fatal("default with no identities")
	}
	alice, _ := NewIdentity("alice", false)
	work, _ := NewIdentity("work", true)
	if err := kr.SaveIdentity(alice, "", false); err != nil {
		t.Fatal(err)
	}
	if err := kr.SaveIdentity(alice, "", false); !errors.Is(err, ErrExists) {
		t.Fatalf("overwrite: %v", err)
	}
	if n, err := kr.DefaultIdentity(); err != nil || n != "alice" {
		t.Fatalf("default: %q %v", n, err)
	}
	if err := kr.SaveIdentity(work, "pw", false); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(kr.Dir, "identities", "work.key")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if _, err := kr.DefaultIdentity(); err == nil {
		t.Fatal("ambiguous default accepted")
	}
	kr.SetDefault("work")
	if n, _ := kr.DefaultIdentity(); n != "work" {
		t.Fatal("SetDefault ignored")
	}
	if locked, _ := kr.IdentityLocked("work"); !locked {
		t.Fatal("work should be locked")
	}

	// Public half is readable without the passphrase.
	pub, err := kr.IdentityPublic("work")
	if err != nil || pub.RecipientString != work.Recipient {
		t.Fatalf("IdentityPublic: %v", err)
	}

	// Lazy identities: a file for alice must not prompt for work's passphrase.
	asked := 0
	u := &Unlocker{Ask: func(string) (string, error) { asked++; return "pw", nil }}
	ids, _ := kr.DecryptionIdentities(u)
	if err := roundTrip(t, alice.Contact().Recipient, ids...); err != nil {
		t.Fatal(err)
	}
	if asked != 0 {
		t.Fatalf("prompted %d times for an unrelated key", asked)
	}
	if err := roundTrip(t, work.Contact().Recipient, ids...); err != nil {
		t.Fatal(err)
	}
	if asked != 1 {
		t.Fatalf("asked %d times", asked)
	}
	// The passphrase is remembered.
	if _, err := kr.LoadIdentity("work", u); err != nil || asked != 1 {
		t.Fatalf("cached passphrase: %v asked=%d", err, asked)
	}

	// No passphrase available (automation): other keys still work and the
	// failure reports why.
	ids, _ = kr.DecryptionIdentities(&Unlocker{})
	err = roundTrip(t, work.Contact().Recipient, ids...)
	var nm *age.NoIdentityMatchError
	if !errors.As(err, &nm) || !errors.Is(err, ErrLocked) {
		t.Fatalf("want NoIdentityMatchError wrapping ErrLocked, got %v", err)
	}
	// Wrong passphrase gives up after a few attempts.
	asked = 0
	_, err = kr.LoadIdentity("work", &Unlocker{Ask: func(string) (string, error) { asked++; return "nope", nil }})
	if !errors.Is(err, ErrBadPassphrase) || asked != maxPassphraseAttempts {
		t.Fatalf("wrong passphrase: %v after %d", err, asked)
	}

	// Contacts and signer lookup.
	bob, _ := NewIdentity("bob", false)
	if err := kr.AddContact(bob.Contact(), false); err != nil {
		t.Fatal(err)
	}
	if c, err := kr.Recipient("bob"); err != nil || c.RecipientString != bob.Recipient {
		t.Fatalf("Recipient(bob): %v", err)
	}
	if c, err := kr.Recipient("alice"); err != nil || c.RecipientString != alice.Recipient {
		t.Fatalf("Recipient(alice): %v", err)
	}
	if _, err := kr.Recipient("carol"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Recipient(carol): %v", err)
	}
	if n, own, ok := kr.SignerName(bob.Signer.Public()); !ok || own || n != "bob" {
		t.Fatalf("SignerName(bob) = %q %v %v", n, own, ok)
	}
	if n, own, ok := kr.SignerName(alice.Signer.Public()); !ok || !own || n != "alice" {
		t.Fatalf("SignerName(alice) = %q %v %v", n, own, ok)
	}
	stranger, _ := NewIdentity("x", false)
	if _, _, ok := kr.SignerName(stranger.Signer.Public()); ok {
		t.Fatal("stranger recognised")
	}
	if names, _ := kr.Contacts(); len(names) != 1 {
		t.Fatalf("contacts %v", names)
	}

	// Legacy keys.
	pem, err := os.ReadFile("../../testdata/legacy/legacy-test.pem")
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.ImportLegacy("old", pem, false); err != nil {
		t.Fatal(err)
	}
	if err := kr.ImportLegacy("junk", []byte("not a key"), false); err == nil {
		t.Fatal("junk legacy key accepted")
	}
	if keys, err := kr.LegacyKeys(); err != nil || len(keys) != 1 {
		t.Fatalf("LegacyKeys: %d %v", len(keys), err)
	}

	// Import of an exported locked identity.
	data, _ := os.ReadFile(filepath.Join(kr.Dir, "identities", "work.key"))
	if _, err := kr.ImportIdentity("work2", data, "pw", false); err != nil {
		t.Fatal(err)
	}

	for _, rm := range []struct {
		kind Kind
		name string
	}{{KindContact, "bob"}, {KindLegacy, "old"}, {KindIdentity, "work2"}} {
		if err := kr.Remove(rm.kind, rm.name); err != nil {
			t.Fatal(err)
		}
		if err := kr.Remove(rm.kind, rm.name); !errors.Is(err, ErrNotFound) {
			t.Fatalf("second remove: %v", err)
		}
	}
	if _, err := os.Stat(filepath.Join(kr.Dir, "identities", "work2.pub")); !os.IsNotExist(err) {
		t.Fatal("sidecar left behind")
	}
}
