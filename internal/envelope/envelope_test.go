package envelope

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"os"
	"slices"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/StuMP90/uencrypt/internal/legacy"
	"github.com/StuMP90/uencrypt/internal/sign"
)

func encrypt(t *testing.T, content []byte, opts EncryptOptions) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := Encrypt(context.Background(), bytes.NewReader(content), &b, opts); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestRecipients(t *testing.T) {
	pq, _ := age.GenerateHybridIdentity()
	pq2, _ := age.GenerateHybridIdentity()
	content := make([]byte, 200000)
	rand.Read(content)

	for _, armor := range []bool{false, true} {
		ct := encrypt(t, content, EncryptOptions{Recipients: []age.Recipient{pq.Recipient(), pq2.Recipient()}, Armor: armor})
		info, err := Inspect(bytes.NewReader(ct))
		if err != nil {
			t.Fatal(err)
		}
		if want := map[bool]Kind{false: KindAge, true: KindAgeArmored}[armor]; info.Kind != want {
			t.Fatalf("kind %v", info.Kind)
		}
		if !slices.Equal(info.Stanzas, []string{"mlkem768x25519"}) || !info.PostQuantum {
			t.Fatalf("info %+v", info)
		}
		// Either identity decrypts; the output is a plain age file.
		for _, id := range []age.Identity{pq, pq2} {
			var out bytes.Buffer
			res, err := Decrypt(context.Background(), bytes.NewReader(ct), &out, DecryptOptions{Identities: []age.Identity{id}})
			if err != nil || !bytes.Equal(out.Bytes(), content) || res.Signed {
				t.Fatalf("decrypt: %v", err)
			}
		}
	}

	x, _ := age.GenerateX25519Identity()
	classic := encrypt(t, []byte("x"), EncryptOptions{Recipients: []age.Recipient{x.Recipient()}})
	if info, _ := Inspect(bytes.NewReader(classic)); info.PostQuantum || !slices.Equal(info.Stanzas, []string{"X25519"}) {
		t.Fatalf("classic file: %+v", info)
	}
	// age refuses to mix classic and post-quantum recipients.
	if err := Encrypt(context.Background(), bytes.NewReader(nil), io.Discard, EncryptOptions{Recipients: []age.Recipient{pq.Recipient(), x.Recipient()}}); err == nil {
		t.Fatal("mixed recipients accepted")
	}
	pqOnly := encrypt(t, []byte("x"), EncryptOptions{Recipients: []age.Recipient{pq.Recipient()}})

	// Wrong key.
	other, _ := age.GenerateHybridIdentity()
	_, err := Decrypt(context.Background(), bytes.NewReader(pqOnly), io.Discard, DecryptOptions{Identities: []age.Identity{other}})
	if !errors.Is(err, ErrNoKey) {
		t.Fatalf("wrong key: %v", err)
	}
}

func TestPassphrase(t *testing.T) {
	ct := encrypt(t, []byte("backup"), EncryptOptions{Passphrase: "hunter2"})
	if info, _ := Inspect(bytes.NewReader(ct)); !slices.Equal(info.Stanzas, []string{"scrypt"}) {
		t.Fatalf("stanzas %v", info.Stanzas)
	}
	answers := []string{"wrong", "hunter2"}
	asked := 0
	var out bytes.Buffer
	_, err := Decrypt(context.Background(), bytes.NewReader(ct), &out, DecryptOptions{
		Passphrase: func() (string, error) { asked++; return answers[asked-1], nil },
	})
	if err != nil || out.String() != "backup" || asked != 2 {
		t.Fatalf("retry: %v asked=%d", err, asked)
	}

	// Gives up after three attempts.
	asked = 0
	_, err = Decrypt(context.Background(), bytes.NewReader(ct), io.Discard, DecryptOptions{
		Passphrase: func() (string, error) { asked++; return "nope", nil },
	})
	if !errors.Is(err, ErrNoKey) || asked != 3 {
		t.Fatalf("give up: %v asked=%d", err, asked)
	}

	// A recipient file never prompts.
	id, _ := age.GenerateHybridIdentity()
	ct = encrypt(t, []byte("x"), EncryptOptions{Recipients: []age.Recipient{id.Recipient()}})
	_, err = Decrypt(context.Background(), bytes.NewReader(ct), io.Discard, DecryptOptions{
		Identities: []age.Identity{id},
		Passphrase: func() (string, error) { t.Fatal("prompted"); return "", nil },
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := Encrypt(context.Background(), nil, io.Discard, EncryptOptions{Passphrase: "p", Recipients: []age.Recipient{id.Recipient()}}); err == nil {
		t.Fatal("passphrase+recipients accepted")
	}
	if err := Encrypt(context.Background(), nil, io.Discard, EncryptOptions{}); err == nil {
		t.Fatal("no recipients accepted")
	}
}

func TestSigned(t *testing.T) {
	id, _ := age.GenerateHybridIdentity()
	sk, _ := sign.Generate()
	content := []byte("signed backup")
	ct := encrypt(t, content, EncryptOptions{Recipients: []age.Recipient{id.Recipient()}, Signer: sk})

	var out bytes.Buffer
	res, err := Decrypt(context.Background(), bytes.NewReader(ct), &out, DecryptOptions{Identities: []age.Identity{id}})
	if err != nil || !bytes.Equal(out.Bytes(), content) {
		t.Fatalf("decrypt: %v", err)
	}
	if !res.Signed || !res.Signer.Equal(sk.Public()) || time.Since(res.SignedAt) > time.Minute {
		t.Fatalf("result %+v", res)
	}

	// Stock age sees the signed container, not an error.
	r, err := age.Decrypt(bytes.NewReader(ct), id)
	if err != nil {
		t.Fatal(err)
	}
	inner, _ := io.ReadAll(r)
	if !sign.IsEmbedded(inner) {
		t.Fatal("inner payload is not a signed container")
	}

	// Signed with passphrase too.
	ct = encrypt(t, content, EncryptOptions{Passphrase: "p", Signer: sk, Armor: true})
	res, err = Decrypt(context.Background(), bytes.NewReader(ct), io.Discard, DecryptOptions{Passphrase: func() (string, error) { return "p", nil }})
	if err != nil || !res.Signed {
		t.Fatalf("passphrase signed: %v", err)
	}
}

func TestDetect(t *testing.T) {
	sk, _ := sign.Generate()
	sig, _ := sign.SignDetached(sk, bytes.NewReader(nil), time.Now())
	if Detect(sig) != KindSignature {
		t.Fatal("signature not detected")
	}
	info, err := Inspect(bytes.NewReader(sig))
	if err != nil || !info.Signer.Equal(sk.Public()) {
		t.Fatalf("inspect signature: %v", err)
	}
	_, err = Decrypt(context.Background(), bytes.NewReader(sig), io.Discard, DecryptOptions{})
	if err == nil {
		t.Fatal("decrypted a signature")
	}
	for _, junk := range []string{"", "hello world", "PK\x03\x04"} {
		if _, err := Decrypt(context.Background(), bytes.NewReader([]byte(junk)), io.Discard, DecryptOptions{}); !errors.Is(err, ErrUnknownFormat) {
			t.Fatalf("%q: %v", junk, err)
		}
	}
}

func TestLegacy(t *testing.T) {
	pem, err := os.ReadFile("../../testdata/legacy/legacy-test.pem")
	if err != nil {
		t.Fatal(err)
	}
	key, err := legacy.ParsePrivateKey(pem)
	if err != nil {
		t.Fatal(err)
	}
	keys := func() ([]*rsa.PrivateKey, error) { return []*rsa.PrivateKey{key}, nil }
	for _, c := range []struct{ dir, name, format string }{
		{"original", "testfile.txt", "legacy-original"},
		{"chunked", "test.txt", "legacy-chunked"},
	} {
		dir := "../../testdata/legacy/" + c.dir + "/"
		want, _ := os.ReadFile(dir + c.name)
		ct, err := os.ReadFile(dir + c.name + ".enc")
		if err != nil {
			t.Fatal(err)
		}
		info, err := Inspect(bytes.NewReader(ct))
		if err != nil || info.Kind != KindLegacy || info.LegacyKeyBits != key.N.BitLen() || info.Legacy.Format.String() != c.format {
			t.Fatalf("inspect %s: %+v %v", c.dir, info, err)
		}
		var out bytes.Buffer
		res, err := Decrypt(context.Background(), bytes.NewReader(ct), &out, DecryptOptions{LegacyKeys: keys})
		if err != nil || !bytes.Equal(out.Bytes(), want) || res.Format != c.format {
			t.Fatalf("%s: %v", c.dir, err)
		}
		if _, err := Decrypt(context.Background(), bytes.NewReader(ct), io.Discard, DecryptOptions{}); !errors.Is(err, ErrNoKey) {
			t.Fatalf("%s without keys: %v", c.dir, err)
		}
		other, _ := rsa.GenerateKey(rand.Reader, 2048)
		_, err = Decrypt(context.Background(), bytes.NewReader(ct), io.Discard, DecryptOptions{
			LegacyKeys: func() ([]*rsa.PrivateKey, error) { return []*rsa.PrivateKey{other}, nil },
		})
		if !errors.Is(err, ErrNoKey) {
			t.Fatalf("%s wrong key: %v", c.dir, err)
		}
	}
}

func TestCancel(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Encrypt(ctx, bytes.NewReader(make([]byte, 1000)), io.Discard, EncryptOptions{Recipients: []age.Recipient{id.Recipient()}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
}

// noSeek hides a reader's Seek method.
type noSeek struct{ io.Reader }

func TestInspectSizes(t *testing.T) {
	a, _ := age.GenerateX25519Identity()
	b, _ := age.GenerateX25519Identity()
	for _, n := range []int{0, 100, 64 * 1024, 64*1024 + 1, 3 * 64 * 1024} {
		for _, armor := range []bool{false, true} {
			ct := encrypt(t, make([]byte, n), EncryptOptions{Recipients: []age.Recipient{a.Recipient(), b.Recipient()}, Armor: armor})
			for _, src := range []io.Reader{bytes.NewReader(ct), noSeek{bytes.NewReader(ct)}} {
				info, err := Inspect(src)
				if err != nil {
					t.Fatal(err)
				}
				if info.Payload != int64(n) || len(info.Recipients) != 2 || info.Recipients[0].Type != "X25519" ||
					!slices.Equal(info.Stanzas, []string{"X25519"}) || info.Overhead != info.Total-int64(n) || info.HeaderSize == 0 {
					t.Fatalf("n=%d armor=%v: %+v", n, armor, info)
				}
				if !armor && info.Total != int64(len(ct)) {
					t.Fatalf("n=%d total %d, want %d", n, info.Total, len(ct))
				}
			}
		}
	}
}
