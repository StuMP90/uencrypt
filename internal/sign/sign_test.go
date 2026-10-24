package sign

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func TestKeyEncoding(t *testing.T) {
	sk, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	sk2, err := ParseSecretKey(sk.String())
	if err != nil {
		t.Fatal(err)
	}
	if !sk.Public().Equal(sk2.Public()) {
		t.Fatal("secret key round trip changed the key")
	}
	pk, err := ParsePublicKey(sk.Public().String())
	if err != nil || !pk.Equal(sk.Public()) {
		t.Fatalf("public key round trip: %v", err)
	}
	if len(pk.Fingerprint()) != 39 {
		t.Fatalf("fingerprint %q", pk.Fingerprint())
	}
}

func TestDetached(t *testing.T) {
	sk, _ := Generate()
	content := []byte("backup contents")
	sig, err := SignDetached(sk, bytes.NewReader(content), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h, err := VerifyDetached(sig, bytes.NewReader(content))
	if err != nil || !h.Signer.Equal(sk.Public()) {
		t.Fatalf("verify: %v", err)
	}
	if _, err := VerifyDetached(sig, bytes.NewReader([]byte("backup contentz"))); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("modified content: %v", err)
	}
	// Swapping in another signer's key must fail.
	other, _ := Generate()
	forged := bytes.Replace(sig, []byte(sk.Public().String()), []byte(other.Public().String()), 1)
	if _, err := VerifyDetached(forged, bytes.NewReader(content)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("swapped signer: %v", err)
	}
}

func TestEmbedded(t *testing.T) {
	sk, _ := Generate()
	for _, size := range []int{0, 1, SignatureSize - 1, SignatureSize, 64*1024 + 7, 300000} {
		content := make([]byte, size)
		rand.Read(content)
		var c bytes.Buffer
		w, err := NewSigningWriter(&c, sk, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		w.Write(content)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if !IsEmbedded(c.Bytes()) {
			t.Fatal("IsEmbedded false")
		}
		var out bytes.Buffer
		h, err := VerifyEmbedded(bytes.NewReader(c.Bytes()), &out)
		if err != nil || !bytes.Equal(out.Bytes(), content) || !h.Signer.Equal(sk.Public()) {
			t.Fatalf("size %d: %v", size, err)
		}
		bad := bytes.Clone(c.Bytes())
		bad[len(bad)-SignatureSize-1-size/2] ^= 1
		if size > 0 {
			if _, err := VerifyEmbedded(bytes.NewReader(bad), &bytes.Buffer{}); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("size %d tampered: %v", size, err)
			}
		}
		if _, err := VerifyEmbedded(bytes.NewReader(c.Bytes()[:c.Len()-1]), &bytes.Buffer{}); err == nil {
			t.Fatalf("size %d truncated accepted", size)
		}
	}
}
