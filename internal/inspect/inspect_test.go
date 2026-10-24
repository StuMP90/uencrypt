package inspect

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"

	"github.com/StuMP90/uencrypt/internal/envelope"
	"github.com/StuMP90/uencrypt/internal/keys"
)

func setup(t *testing.T) (string, *keys.Keyring) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir) // no real ~/.ssh keys
	kr, err := keys.Open(filepath.Join(dir, "keyring"))
	if err != nil {
		t.Fatal(err)
	}
	return dir, kr
}

func write(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func encrypt(t *testing.T, plain []byte, opts envelope.EncryptOptions) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := envelope.Encrypt(context.Background(), bytes.NewReader(plain), &b, opts); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func zipData(t *testing.T) []byte {
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	w, _ := zw.Create("notes.txt")
	w.Write([]byte("hello"))
	zw.Close()
	return b.Bytes()
}

func TestAgeRecipients(t *testing.T) {
	dir, kr := setup(t)
	id, err := keys.NewIdentity("me", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.SaveIdentity(id, "", false); err != nil {
		t.Fatal(err)
	}
	other, _ := age.GenerateX25519Identity()

	// An SSH key of our own in ~/.ssh.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "")
	os.Mkdir(filepath.Join(dir, ".ssh"), 0o700)
	write(t, filepath.Join(dir, ".ssh"), "id_ed25519", pem.EncodeToMemory(block))
	sshPub, _ := ssh.NewPublicKey(pub)
	sshRcpt, _ := agessh.NewEd25519Recipient(sshPub)

	ct := encrypt(t, zipData(t), envelope.EncryptOptions{
		Recipients: []age.Recipient{id.Contact().Recipient, other.Recipient(), sshRcpt}, Armor: true})
	path := write(t, dir, "f.age", ct)

	ids, _ := kr.DecryptionIdentities(nil)
	rep, err := File(context.Background(), path, Options{Keyring: kr, Contents: true,
		Decrypt: envelope.DecryptOptions{Identities: ids}})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Kind != "age" || !rep.Armored || rep.PostQuantum || len(rep.Recipients) != 2 || rep.Recipients[0].Count != 2 {
		t.Fatalf("%+v", rep)
	}
	if r := rep.Recipients[1]; r.Type != "ssh-ed25519" || len(r.Keys) != 1 || r.Keys[0] != "~/.ssh/id_ed25519" {
		t.Errorf("ssh: %+v", r)
	}
	if !strings.HasPrefix(rep.Access, "yes") {
		t.Errorf("access %q", rep.Access)
	}
	if rep.Sizes.Payload != int64(len(zipData(t))) {
		t.Errorf("sizes %+v", rep.Sizes)
	}
	if rep.Content == nil || rep.Content.Type != "zip" || rep.Signed == nil || *rep.Signed {
		t.Errorf("content %+v %v (%s)", rep.Content, rep.Signed, rep.ContentsError)
	}
}

func TestPassphraseAndPostQuantum(t *testing.T) {
	dir, kr := setup(t)
	p := write(t, dir, "p.age", encrypt(t, []byte("x"), envelope.EncryptOptions{Passphrase: "pw"}))
	rep, err := File(context.Background(), p, Options{Keyring: kr, Contents: true,
		Decrypt: envelope.DecryptOptions{Passphrase: func() (string, error) { return "wrong", nil }}})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.PostQuantum || !strings.Contains(rep.Access, "passphrase") || rep.Content != nil || rep.ContentsError == "" {
		t.Fatalf("%+v", rep)
	}

	id, _ := keys.NewIdentity("me", false)
	kr.SaveIdentity(id, "", false)
	other, _ := keys.NewIdentity("other", false)
	p = write(t, dir, "pq.age", encrypt(t, []byte("x"), envelope.EncryptOptions{
		Recipients: []age.Recipient{other.Contact().Recipient}}))
	rep, err = File(context.Background(), p, Options{Keyring: kr})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.PostQuantum || rep.Recipients[0].Unidentified != 1 || !strings.HasPrefix(rep.Access, "possibly") {
		t.Fatalf("%+v", rep)
	}
}

func TestLegacy(t *testing.T) {
	dir, kr := setup(t)
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	if err := kr.ImportLegacy("old", pemData, false); err != nil {
		t.Fatal(err)
	}
	// One chunk, so the chunk nonce is the base nonce.
	fk, nonce := make([]byte, 32), make([]byte, 12)
	rand.Read(fk)
	rand.Read(nonce)
	wrapped, _ := rsa.EncryptPKCS1v15(rand.Reader, &k.PublicKey, fk)
	blk, _ := aes.NewCipher(fk)
	aead, _ := cipher.NewGCM(blk)
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, uint32(len(wrapped)))
	b.Write(wrapped)
	b.Write(nonce)
	chunk := aead.Seal(nil, nonce, zipData(t), nil)
	binary.Write(&b, binary.BigEndian, uint32(len(chunk)))
	b.Write(chunk)
	b.Write([]byte{0, 0, 0, 0})
	p := write(t, dir, "f.enc", b.Bytes())

	rep, err := File(context.Background(), p, Options{Keyring: kr, Contents: true,
		Decrypt: envelope.DecryptOptions{LegacyKeys: kr.LegacyKeys}})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Format != "legacy-chunked" || rep.Legacy.Key != "old" || rep.Legacy.Chunks != 1 ||
		rep.Legacy.KeyBits != 2048 || len(rep.Warnings) != 1 || rep.Content == nil || rep.Content.Type != "zip" {
		t.Fatalf("%+v %+v (%s)", rep, rep.Legacy, rep.ContentsError)
	}
}

func TestPlain(t *testing.T) {
	dir, _ := setup(t)
	rep, err := File(context.Background(), write(t, dir, "a.zip", zipData(t)), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Kind != "plain" || rep.Format != "zip" || rep.Content.EntryCount != 1 {
		t.Fatalf("%+v", rep)
	}
}
