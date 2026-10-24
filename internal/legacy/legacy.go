// Package legacy decrypts files produced by the older ppkencrypt and
// oakcryptor tools. It is read-only: uencrypt never writes these formats.
//
// Both formats start with an RSA PKCS#1 v1.5 wrapped AES-256 key:
//
//	[4-byte BE key length][RSA-encrypted AES key][12-byte GCM nonce]
//
// The original format follows that with a single AES-GCM ciphertext. The
// chunked format follows it with records of [4-byte BE length][GCM chunk],
// terminated by a zero length. Chunk n uses the base nonce with its last
// eight bytes XORed with n (big-endian).
//
// The chunked end marker is not authenticated, so an attacker who can modify
// the file can drop whole trailing chunks without detection. Callers should
// surface Result.Warnings to the user.
package legacy

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

// Format identifies which legacy layout a file uses.
type Format int

const (
	Original Format = iota + 1
	Chunked
)

func (f Format) String() string {
	switch f {
	case Original:
		return "legacy-original"
	case Chunked:
		return "legacy-chunked"
	}
	return "unknown"
}

const (
	nonceSize = 12
	tagSize   = 16
	// The old encryptor used 1 MB chunks by default and its decryptor
	// accepted up to 100 MB; anything larger is not a legacy file.
	maxChunk = 100*1024*1024 + tagSize
	// The original format was decrypted in memory by the old tools too.
	maxOriginal = 4 << 30
)

var (
	// ErrNotLegacy means the data does not look like a legacy file.
	ErrNotLegacy = errors.New("not a legacy ppkencrypt/oakcryptor file")
	// ErrWrongKey means none of the supplied RSA keys could unwrap the file key.
	ErrWrongKey = errors.New("none of the legacy RSA keys can decrypt this file")
	// ErrTruncated means a chunked file ended without its end marker.
	ErrTruncated = errors.New("legacy file is truncated (missing end marker)")
)

// TamperWarning is attached to every successful chunked decryption.
const TamperWarning = "legacy chunked format: removal of whole trailing chunks cannot be detected"

// Result describes a successful decryption.
type Result struct {
	Format   Format
	Chunks   int
	Warnings []string
}

// Sniff reports whether header (the first bytes of a file, at least 4) could
// be the start of a legacy file. It only checks the RSA key length field.
func Sniff(header []byte) bool {
	if len(header) < 4 {
		return false
	}
	n := binary.BigEndian.Uint32(header)
	// RSA-1024 to RSA-16384 ciphertexts.
	return n >= 128 && n <= 2048 && n%64 == 0
}

// ParsePrivateKey parses a PEM-encoded RSA private key in PKCS#8 or PKCS#1
// form, as accepted by the old tools.
func ParsePrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if block.Type != "PRIVATE KEY" && block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("PKCS#8 key is not an RSA key")
		}
		return rk, nil
	}
	rk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing RSA private key: %w", err)
	}
	return rk, nil
}

// Decrypt reads a legacy file from src and writes the plaintext to dst,
// trying each key in turn. For the chunked format, plaintext is streamed, so
// dst may have received data before an error is returned; callers should
// write to a temporary location and discard it on error.
func Decrypt(src io.Reader, dst io.Writer, keys ...*rsa.PrivateKey) (*Result, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(src, lenBuf[:]); err != nil {
		return nil, ErrNotLegacy
	}
	if !Sniff(lenBuf[:]) {
		return nil, ErrNotLegacy
	}
	wrapped := make([]byte, binary.BigEndian.Uint32(lenBuf[:]))
	if _, err := io.ReadFull(src, wrapped); err != nil {
		return nil, ErrNotLegacy
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(src, nonce); err != nil {
		return nil, ErrNotLegacy
	}

	aead, err := unwrapKey(wrapped, keys)
	if err != nil {
		return nil, err
	}

	// The old decryptor guessed the format from the next four bytes alone,
	// which misdetects about 2% of original-format files. Instead, try the
	// first chunk and fall back to the original format if it fails to
	// authenticate, replaying whatever was consumed.
	br := bufio.NewReaderSize(src, 64*1024)
	var consumed bytes.Buffer
	tee := io.TeeReader(br, &consumed)

	if _, err := io.ReadFull(tee, lenBuf[:]); err == nil {
		n := binary.BigEndian.Uint32(lenBuf[:])
		switch {
		case n == 0:
			// Empty chunked file: just the end marker.
			if _, err := br.Peek(1); err == io.EOF {
				return &Result{Format: Chunked, Warnings: []string{TamperWarning}}, nil
			}
		case n >= tagSize && n <= maxChunk:
			chunk := make([]byte, n)
			if _, err := io.ReadFull(tee, chunk); err == nil {
				if pt, err := aead.Open(chunk[:0], chunkNonce(nonce, 0), chunk, nil); err == nil {
					if _, err := dst.Write(pt); err != nil {
						return nil, err
					}
					return decryptChunks(br, dst, aead, nonce)
				}
			}
		}
	}

	rest, err := io.ReadAll(io.LimitReader(io.MultiReader(bytes.NewReader(consumed.Bytes()), br), maxOriginal+1))
	if err != nil {
		return nil, err
	}
	if len(rest) > maxOriginal {
		return nil, errors.New("legacy original-format file is too large")
	}
	pt, err := aead.Open(rest[:0], nonce, rest, nil)
	if err != nil {
		return nil, errors.New("legacy file failed authentication: it is corrupted or has been modified")
	}
	if _, err := dst.Write(pt); err != nil {
		return nil, err
	}
	return &Result{Format: Original}, nil
}

// decryptChunks continues a chunked file after chunk 0 has been written.
func decryptChunks(r io.Reader, dst io.Writer, aead cipher.AEAD, nonce []byte) (*Result, error) {
	var lenBuf [4]byte
	buf := make([]byte, 0, 1024*1024+tagSize)
	for n := uint64(1); ; n++ {
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil, ErrTruncated
			}
			return nil, err
		}
		size := binary.BigEndian.Uint32(lenBuf[:])
		if size == 0 {
			res := &Result{Format: Chunked, Chunks: int(n), Warnings: []string{TamperWarning}}
			var extra [1]byte
			if m, _ := r.Read(extra[:]); m > 0 {
				res.Warnings = append(res.Warnings, "legacy file has unexpected data after the end marker (ignored)")
			}
			return res, nil
		}
		if size < tagSize || size > maxChunk {
			return nil, fmt.Errorf("legacy chunk %d has an invalid length", n)
		}
		if cap(buf) < int(size) {
			buf = make([]byte, 0, size)
		}
		chunk := buf[:size]
		if _, err := io.ReadFull(r, chunk); err != nil {
			return nil, ErrTruncated
		}
		pt, err := aead.Open(chunk[:0], chunkNonce(nonce, n), chunk, nil)
		if err != nil {
			return nil, fmt.Errorf("legacy chunk %d failed authentication: the file is corrupted or has been modified", n)
		}
		if _, err := dst.Write(pt); err != nil {
			return nil, err
		}
	}
}

func chunkNonce(base []byte, n uint64) []byte {
	out := make([]byte, nonceSize)
	copy(out, base)
	for i := 0; i < 8; i++ {
		out[nonceSize-1-i] ^= byte(n >> (8 * i))
	}
	return out
}

func unwrapKey(wrapped []byte, keys []*rsa.PrivateKey) (cipher.AEAD, error) {
	if len(keys) == 0 {
		return nil, errors.New("this is a legacy RSA-encrypted file; a legacy .pem private key is required")
	}
	for _, k := range keys {
		if key := fileKey(wrapped, k); key != nil {
			block, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}
			return cipher.NewGCM(block)
		}
	}
	return nil, ErrWrongKey
}

// fileKey returns the AES key wrapped to k, or nil.
func fileKey(wrapped []byte, k *rsa.PrivateKey) []byte {
	if k == nil || k.Size() != len(wrapped) {
		return nil
	}
	key, err := rsa.DecryptPKCS1v15(nil, k, wrapped)
	if err != nil || len(key) != 32 {
		return nil
	}
	return key
}

// MatchKey returns the index of the key that a file's wrapped key (from
// Inspect) was encrypted to, or -1.
func MatchKey(wrapped []byte, keys []*rsa.PrivateKey) int {
	for i, k := range keys {
		if fileKey(wrapped, k) != nil {
			return i
		}
	}
	return -1
}

// Details is what Inspect can tell about a legacy file without its key.
type Details struct {
	KeyBits int
	// WrappedKey is the RSA-encrypted file key, for MatchKey.
	WrappedKey []byte
	Format     Format
	// Chunks and ChunkSize (the plaintext size of the first chunk) are
	// set for the chunked format.
	Chunks    int
	ChunkSize int64
	// Truncated is set when the file looks like a chunked file whose end
	// is missing.
	Truncated bool
	// HeaderSize covers the key length, wrapped key and nonce; Overhead is
	// everything that is not plaintext (including the header).
	HeaderSize, Overhead, Payload, Total int64
}

// Inspect reads a legacy file's structure. Without the key, the format
// is found from the chunk lengths: a chain of valid lengths that ends with
// the end marker exactly at the end of the file is the chunked format (an
// original-format file matching by chance is vanishingly unlikely). It
// seeks over the data when r is an io.Seeker.
func Inspect(r io.Reader) (*Details, error) {
	w := &walker{r: r, end: -1}
	if s, ok := r.(io.Seeker); ok {
		if cur, err := s.Seek(0, io.SeekCurrent); err == nil {
			if end, err := s.Seek(0, io.SeekEnd); err == nil {
				w.s, w.off, w.end = s, cur, end
			}
			if _, err := s.Seek(cur, io.SeekStart); err != nil {
				return nil, err
			}
		}
	}
	start := w.off
	var lenBuf [4]byte
	if w.read(lenBuf[:]) != nil || !Sniff(lenBuf[:]) {
		return nil, ErrNotLegacy
	}
	d := &Details{WrappedKey: make([]byte, binary.BigEndian.Uint32(lenBuf[:]))}
	d.KeyBits = len(d.WrappedKey) * 8
	if w.read(d.WrappedKey) != nil || w.skip(nonceSize) != nil {
		return nil, ErrNotLegacy
	}
	d.HeaderSize = w.off - start

	chunked := false
	var payload int64
	for n := 0; ; n++ {
		if w.read(lenBuf[:]) != nil {
			d.Truncated = n >= 2
			break
		}
		size := int64(binary.BigEndian.Uint32(lenBuf[:]))
		if size == 0 {
			var b [1]byte
			chunked = w.read(b[:]) == io.EOF
			if chunked {
				d.Chunks = n
			}
			break
		}
		if size < tagSize || size > maxChunk {
			break
		}
		if w.skip(size) != nil {
			d.Truncated = n >= 1
			break
		}
		if n == 0 {
			d.ChunkSize = size - tagSize
		}
		payload += size - tagSize
	}
	if w.end < 0 {
		if _, err := io.Copy(io.Discard, w); err != nil {
			return nil, err
		}
		w.end = w.off
	} else {
		w.off = w.end
	}
	d.Total = w.off - start
	if chunked {
		d.Format, d.Payload = Chunked, payload
		d.Truncated = false
	} else {
		d.Format, d.ChunkSize = Original, 0
		d.Payload = max(d.Total-d.HeaderSize-tagSize, 0)
	}
	d.Overhead = d.Total - d.Payload
	return d, nil
}

// walker reads or skips through a file, tracking the offset.
type walker struct {
	r        io.Reader
	s        io.Seeker
	off, end int64
}

func (w *walker) Read(p []byte) (int, error) {
	n, err := w.r.Read(p)
	w.off += int64(n)
	return n, err
}

func (w *walker) read(p []byte) error {
	_, err := io.ReadFull(w, p)
	return err
}

func (w *walker) skip(n int64) error {
	if w.s == nil {
		m, err := io.CopyN(io.Discard, w, n)
		if m < n {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	if w.off+n > w.end {
		return io.ErrUnexpectedEOF
	}
	if _, err := w.s.Seek(n, io.SeekCurrent); err != nil {
		return err
	}
	w.off += n
	return nil
}
