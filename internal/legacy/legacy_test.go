package legacy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	data, err := os.ReadFile("../../testdata/legacy/legacy-test.pem")
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParsePrivateKey(data)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestFixtures(t *testing.T) {
	key := testKey(t)
	for _, tc := range []struct {
		dir    string
		format Format
	}{
		{"original", Original},
		{"chunked", Chunked},
	} {
		for _, name := range []string{"testfile.txt", "test.txt"} {
			t.Run(tc.dir+"/"+name, func(t *testing.T) {
				dir := filepath.Join("../../testdata/legacy", tc.dir)
				want, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					t.Fatal(err)
				}
				f, err := os.Open(filepath.Join(dir, name+".enc"))
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				var out bytes.Buffer
				res, err := Decrypt(f, &out, key)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(out.Bytes(), want) {
					t.Fatalf("plaintext mismatch: got %q", out.Bytes())
				}
				// test.txt.enc was produced by the original tool in both folders.
				if name == "testfile.txt" && res.Format != tc.format {
					t.Fatalf("format = %v, want %v", res.Format, tc.format)
				}
			})
		}
	}
}

// writeChunked produces the oakcryptor chunked format, for tests only.
func writeChunked(t *testing.T, pub *rsa.PublicKey, plain []byte, chunkSize int) []byte {
	t.Helper()
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	rand.Read(key)
	rand.Read(nonce)
	wrapped, err := rsa.EncryptPKCS1v15(rand.Reader, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, uint32(len(wrapped)))
	b.Write(wrapped)
	b.Write(nonce)
	for n := uint64(0); len(plain) > 0; n++ {
		m := min(chunkSize, len(plain))
		ct := aead.Seal(nil, chunkNonce(nonce, n), plain[:m], nil)
		binary.Write(&b, binary.BigEndian, uint32(len(ct)))
		b.Write(ct)
		plain = plain[m:]
	}
	b.Write([]byte{0, 0, 0, 0})
	return b.Bytes()
}

func writeOriginal(t *testing.T, pub *rsa.PublicKey, plain []byte) []byte {
	t.Helper()
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	rand.Read(key)
	rand.Read(nonce)
	wrapped, _ := rsa.EncryptPKCS1v15(rand.Reader, pub, key)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, uint32(len(wrapped)))
	b.Write(wrapped)
	b.Write(nonce)
	b.Write(aead.Seal(nil, nonce, plain, nil))
	return b.Bytes()
}

func TestMultiChunkAndTruncation(t *testing.T) {
	key := testKey(t)
	plain := make([]byte, 10000)
	rand.Read(plain)
	enc := writeChunked(t, &key.PublicKey, plain, 1024)

	var out bytes.Buffer
	res, err := Decrypt(bytes.NewReader(enc), &out, key)
	if err != nil || !bytes.Equal(out.Bytes(), plain) || res.Format != Chunked || res.Chunks != 10 {
		t.Fatalf("round trip failed: %v %+v", err, res)
	}

	// Missing end marker.
	_, err = Decrypt(bytes.NewReader(enc[:len(enc)-4]), &bytes.Buffer{}, key)
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("want ErrTruncated, got %v", err)
	}
	// Cut mid-chunk.
	_, err = Decrypt(bytes.NewReader(enc[:len(enc)-500]), &bytes.Buffer{}, key)
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("want ErrTruncated, got %v", err)
	}
	// Flipped bit in a later chunk.
	bad := bytes.Clone(enc)
	bad[len(bad)-100] ^= 1
	if _, err = Decrypt(bytes.NewReader(bad), &bytes.Buffer{}, key); err == nil {
		t.Fatal("tampered chunk accepted")
	}
}

func TestOriginalFallback(t *testing.T) {
	// Original-format files whose ciphertext happens to start with a
	// plausible chunk length must still decrypt.
	key := testKey(t)
	for i := 0; i < 200; i++ {
		plain := make([]byte, 64+i)
		rand.Read(plain)
		enc := writeOriginal(t, &key.PublicKey, plain)
		var out bytes.Buffer
		res, err := Decrypt(bytes.NewReader(enc), &out, key)
		if err != nil || !bytes.Equal(out.Bytes(), plain) || res.Format != Original {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}
	enc := writeOriginal(t, &key.PublicKey, []byte("hello"))
	enc[len(enc)-1] ^= 1
	if _, err := Decrypt(bytes.NewReader(enc), &bytes.Buffer{}, key); err == nil {
		t.Fatal("tampered original accepted")
	}
}

func TestEmptyAndWrongKey(t *testing.T) {
	key := testKey(t)
	for _, enc := range [][]byte{writeChunked(t, &key.PublicKey, nil, 1024), writeOriginal(t, &key.PublicKey, nil)} {
		var out bytes.Buffer
		if _, err := Decrypt(bytes.NewReader(enc), &out, key); err != nil || out.Len() != 0 {
			t.Fatalf("empty: %v", err)
		}
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	enc := writeOriginal(t, &key.PublicKey, []byte("x"))
	if _, err := Decrypt(bytes.NewReader(enc), &bytes.Buffer{}, other); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("want ErrWrongKey, got %v", err)
	}
	if _, err := Decrypt(bytes.NewReader([]byte("age-encryption.org/v1\n")), &bytes.Buffer{}, key); !errors.Is(err, ErrNotLegacy) {
		t.Fatalf("want ErrNotLegacy, got %v", err)
	}
}

// noSeek hides a reader's Seek method.
type noSeek struct{ r *bytes.Reader }

func (n noSeek) Read(p []byte) (int, error) { return n.r.Read(p) }

func TestInspect(t *testing.T) {
	key := testKey(t)
	plain := make([]byte, 10000)
	rand.Read(plain)
	chunked := writeChunked(t, &key.PublicKey, plain, 1024)
	header := int64(4 + 256 + 12)
	for _, seek := range []bool{true, false} {
		in := func(b []byte) io.Reader {
			if seek {
				return bytes.NewReader(b)
			}
			return noSeek{bytes.NewReader(b)}
		}
		d, err := Inspect(in(chunked))
		if err != nil {
			t.Fatal(err)
		}
		want := Details{KeyBits: 2048, WrappedKey: d.WrappedKey, Format: Chunked, Chunks: 10, ChunkSize: 1024,
			HeaderSize: header, Payload: 10000, Total: int64(len(chunked)), Overhead: int64(len(chunked)) - 10000}
		if !reflect.DeepEqual(*d, want) || d.Overhead != header+10*20+4 {
			t.Fatalf("seek=%v chunked: %+v", seek, d)
		}
		if MatchKey(d.WrappedKey, []*rsa.PrivateKey{nil, key}) != 1 {
			t.Fatal("key not matched")
		}

		if d, _ = Inspect(in(chunked[:len(chunked)-4])); d.Format != Original || !d.Truncated {
			t.Fatalf("seek=%v truncated: %+v", seek, d)
		}

		orig := writeOriginal(t, &key.PublicKey, plain)
		if d, _ = Inspect(in(orig)); d.Format != Original || d.Payload != 10000 || d.Truncated || d.Total != int64(len(orig)) {
			t.Fatalf("seek=%v original: %+v", seek, d)
		}
		if d, _ = Inspect(in(writeChunked(t, &key.PublicKey, nil, 1024))); d.Format != Chunked || d.Chunks != 0 || d.Payload != 0 {
			t.Fatalf("seek=%v empty: %+v", seek, d)
		}
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	d, _ := Inspect(bytes.NewReader(chunked))
	if MatchKey(d.WrappedKey, []*rsa.PrivateKey{other}) != -1 {
		t.Fatal("wrong key matched")
	}
	if _, err := Inspect(bytes.NewReader([]byte("age-encryption.org/v1\n"))); !errors.Is(err, ErrNotLegacy) {
		t.Fatal(err)
	}
}
