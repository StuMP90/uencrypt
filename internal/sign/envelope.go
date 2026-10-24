package sign

import (
	"bufio"
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
	"time"
)

// Two signature encodings share one signed-message construction:
//
// Detached (.sig files, signing without encryption):
//
//	-----BEGIN UENCRYPT SIGNATURE-----
//	Signer: uesig1...
//	Created: 2026-10-23T12:00:00Z
//
//	<base64 signature>
//	-----END UENCRYPT SIGNATURE-----
//
// Embedded (sign+encrypt; this is the plaintext inside the age file):
//
//	uencrypt-signed/v1\n
//	Signer: uesig1...\n
//	Created: ...\n
//	\n
//	<content><SignatureSize-byte signature>
//
// The signed message is a domain string, the kind, the header lines and the
// SHA-512 of the content, so a detached signature can't be replayed as an
// embedded one or vice versa.

const (
	EmbeddedMagic = "uencrypt-signed/v1\n"
	detachedBegin = "-----BEGIN UENCRYPT SIGNATURE-----"
	detachedEnd   = "-----END UENCRYPT SIGNATURE-----"

	kindDetached = "detached"
	kindEmbedded = "embedded"

	maxHeaderLine = 8 * 1024
	maxHeaderRows = 16
)

// Header is the signed metadata carried with a signature.
type Header struct {
	Signer  *PublicKey
	Created time.Time
}

func (h *Header) lines() string {
	return "Signer: " + h.Signer.String() + "\nCreated: " + h.Created.UTC().Format(time.RFC3339) + "\n"
}

func message(kind string, h *Header, digest []byte) []byte {
	var b bytes.Buffer
	b.WriteString("uencrypt-signature-v1\n")
	b.WriteString(kind + "\n")
	b.WriteString(h.lines())
	b.Write(digest)
	return b.Bytes()
}

func parseHeaderLines(r *bufio.Reader) (*Header, error) {
	h := &Header{}
	for i := 0; ; i++ {
		if i > maxHeaderRows {
			return nil, errors.New("signature header too long")
		}
		line, err := readLine(r)
		if err != nil {
			return nil, err
		}
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, ": ")
		if !ok {
			return nil, fmt.Errorf("malformed signature header line %q", line)
		}
		switch k {
		case "Signer":
			if h.Signer, err = ParsePublicKey(v); err != nil {
				return nil, err
			}
		case "Created":
			if h.Created, err = time.Parse(time.RFC3339, v); err != nil {
				return nil, fmt.Errorf("bad Created time: %w", err)
			}
		default:
			return nil, fmt.Errorf("unknown signature header %q", k)
		}
	}
	if h.Signer == nil || h.Created.IsZero() {
		return nil, errors.New("signature header is incomplete")
	}
	return h, nil
}

func readLine(r *bufio.Reader) (string, error) {
	var b []byte
	for {
		part, isPrefix, err := r.ReadLine()
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return "", err
		}
		b = append(b, part...)
		if len(b) > maxHeaderLine {
			return "", errors.New("signature header line too long")
		}
		if !isPrefix {
			return strings.TrimSuffix(string(b), "\r"), nil
		}
	}
}

// SignDetached hashes content and returns an armored detached signature.
func SignDetached(sk *SecretKey, content io.Reader, now time.Time) ([]byte, error) {
	d := sha512.New()
	if _, err := io.Copy(d, content); err != nil {
		return nil, err
	}
	h := &Header{Signer: sk.Public(), Created: now.Truncate(time.Second)}
	sig, err := sk.Sign(message(kindDetached, h, d.Sum(nil)))
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString(detachedBegin + "\n")
	b.WriteString(h.lines())
	b.WriteString("\n")
	enc := base64.StdEncoding.EncodeToString(sig)
	for len(enc) > 64 {
		b.WriteString(enc[:64] + "\n")
		enc = enc[64:]
	}
	b.WriteString(enc + "\n" + detachedEnd + "\n")
	return b.Bytes(), nil
}

// ParseDetached parses an armored detached signature without checking it.
func ParseDetached(sigText []byte) (*Header, []byte, error) {
	r := bufio.NewReader(bytes.NewReader(sigText))
	first, err := readLine(r)
	if err != nil || strings.TrimSpace(first) != detachedBegin {
		return nil, nil, errors.New("not a uencrypt signature file")
	}
	h, err := parseHeaderLines(r)
	if err != nil {
		return nil, nil, err
	}
	var enc strings.Builder
	for {
		line, err := readLine(r)
		if err != nil {
			return nil, nil, errors.New("signature file is truncated")
		}
		if strings.TrimSpace(line) == detachedEnd {
			break
		}
		enc.WriteString(strings.TrimSpace(line))
	}
	sig, err := base64.StdEncoding.DecodeString(enc.String())
	if err != nil {
		return nil, nil, errors.New("signature file is corrupted")
	}
	return h, sig, nil
}

// VerifyDetached checks a detached signature over content. The returned
// header is only trustworthy when err is nil; callers must still decide
// whether they trust Header.Signer.
func VerifyDetached(sigText []byte, content io.Reader) (*Header, error) {
	h, sig, err := ParseDetached(sigText)
	if err != nil {
		return nil, err
	}
	d := sha512.New()
	if _, err := io.Copy(d, content); err != nil {
		return nil, err
	}
	return h, h.Signer.Verify(message(kindDetached, h, d.Sum(nil)), sig)
}

// signingWriter streams content into an embedded signed container.
type signingWriter struct {
	w      io.Writer
	sk     *SecretKey
	h      *Header
	digest hash.Hash
}

// NewSigningWriter writes the embedded container header to w and returns a
// writer for the content. Close appends the signature; it does not close w.
func NewSigningWriter(w io.Writer, sk *SecretKey, now time.Time) (io.WriteCloser, error) {
	h := &Header{Signer: sk.Public(), Created: now.Truncate(time.Second)}
	if _, err := io.WriteString(w, EmbeddedMagic+h.lines()+"\n"); err != nil {
		return nil, err
	}
	return &signingWriter{w: w, sk: sk, h: h, digest: sha512.New()}, nil
}

func (s *signingWriter) Write(p []byte) (int, error) {
	n, err := s.w.Write(p)
	s.digest.Write(p[:n])
	return n, err
}

func (s *signingWriter) Close() error {
	sig, err := s.sk.Sign(message(kindEmbedded, s.h, s.digest.Sum(nil)))
	if err != nil {
		return err
	}
	_, err = s.w.Write(sig)
	return err
}

// IsEmbedded reports whether prefix starts an embedded signed container.
func IsEmbedded(prefix []byte) bool {
	return bytes.HasPrefix(prefix, []byte(EmbeddedMagic))
}

// ErrTruncated means an embedded container ended before its signature.
var ErrTruncated = errors.New("signed content is truncated")

// VerifyEmbedded reads an embedded container from r, streaming the content
// to dst and checking the signature at the end. dst receives content before
// verification completes, so callers must discard it unless err is nil.
// On ErrBadSignature the header is returned so the signer can be reported.
func VerifyEmbedded(r io.Reader, dst io.Writer) (*Header, error) {
	br := bufio.NewReaderSize(r, 64*1024)
	magic := make([]byte, len(EmbeddedMagic))
	if _, err := io.ReadFull(br, magic); err != nil || string(magic) != EmbeddedMagic {
		return nil, errors.New("not a uencrypt signed container")
	}
	h, err := parseHeaderLines(br)
	if err != nil {
		return nil, err
	}
	d := sha512.New()
	out := io.MultiWriter(dst, d)

	// Hold back the last SignatureSize bytes: they are the signature.
	buf := make([]byte, 64*1024+SignatureSize)
	held := 0
	for {
		n, err := br.Read(buf[held:])
		held += n
		if held > SignatureSize {
			emit := held - SignatureSize
			if _, werr := out.Write(buf[:emit]); werr != nil {
				return nil, werr
			}
			held = copy(buf, buf[emit:held])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if held < SignatureSize {
		return h, ErrTruncated
	}
	return h, h.Signer.Verify(message(kindEmbedded, h, d.Sum(nil)), buf[:SignatureSize])
}
