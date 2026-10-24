// Package sign implements uencrypt's hybrid signatures: every signature is an
// Ed25519 signature and an ML-DSA-65 signature over the same message, and
// both must verify. This stays secure if either algorithm is broken.
package sign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	SecretPrefix = "UENCRYPT-SIGN-SECRET-KEY-1"
	PublicPrefix = "uesig1"

	// mldsaContext domain-separates uencrypt signatures from any other use
	// of the same ML-DSA key.
	mldsaContext = "uencrypt-v1"

	publicSize    = ed25519.PublicKeySize + mldsa.MLDSA65PublicKeySize
	SignatureSize = ed25519.SignatureSize + mldsa.MLDSA65SignatureSize
)

var b64 = base64.RawURLEncoding

// SecretKey is a hybrid signing key.
type SecretKey struct {
	ed ed25519.PrivateKey
	ml *mldsa.PrivateKey
}

// PublicKey is a hybrid verification key.
type PublicKey struct {
	ed ed25519.PublicKey
	ml *mldsa.PublicKey
}

// Generate creates a new random signing key.
func Generate() (*SecretKey, error) {
	seed := make([]byte, ed25519.SeedSize+mldsa.PrivateKeySize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return fromSeed(seed)
}

func fromSeed(seed []byte) (*SecretKey, error) {
	ml, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed[ed25519.SeedSize:])
	if err != nil {
		return nil, err
	}
	return &SecretKey{ed: ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize]), ml: ml}, nil
}

// ParseSecretKey parses the output of SecretKey.String.
func ParseSecretKey(s string) (*SecretKey, error) {
	enc, ok := strings.CutPrefix(strings.TrimSpace(s), SecretPrefix)
	if !ok {
		return nil, errors.New("not a uencrypt signing key")
	}
	seed, err := b64.DecodeString(enc)
	if err != nil || len(seed) != ed25519.SeedSize+mldsa.PrivateKeySize {
		return nil, errors.New("malformed uencrypt signing key")
	}
	return fromSeed(seed)
}

// String encodes the secret key (both 32-byte seeds).
func (k *SecretKey) String() string {
	return SecretPrefix + b64.EncodeToString(append(k.ed.Seed(), k.ml.Bytes()...))
}

// Public returns the verification key.
func (k *SecretKey) Public() *PublicKey {
	return &PublicKey{ed: k.ed.Public().(ed25519.PublicKey), ml: k.ml.PublicKey()}
}

// Sign signs msg with both algorithms. The result is SignatureSize bytes.
func (k *SecretKey) Sign(msg []byte) ([]byte, error) {
	mlSig, err := k.ml.Sign(nil, msg, &mldsa.Options{Context: mldsaContext})
	if err != nil {
		return nil, err
	}
	return append(ed25519.Sign(k.ed, msg), mlSig...), nil
}

// ParsePublicKey parses the output of PublicKey.String.
func ParsePublicKey(s string) (*PublicKey, error) {
	enc, ok := strings.CutPrefix(strings.TrimSpace(s), PublicPrefix)
	if !ok {
		return nil, errors.New("not a uencrypt signing public key")
	}
	raw, err := b64.DecodeString(enc)
	if err != nil || len(raw) != publicSize {
		return nil, errors.New("malformed uencrypt signing public key")
	}
	return publicFromBytes(raw)
}

func publicFromBytes(raw []byte) (*PublicKey, error) {
	ml, err := mldsa.NewPublicKey(mldsa.MLDSA65(), raw[ed25519.PublicKeySize:])
	if err != nil {
		return nil, err
	}
	return &PublicKey{ed: ed25519.PublicKey(bytes.Clone(raw[:ed25519.PublicKeySize])), ml: ml}, nil
}

// Bytes returns the raw encoding: Ed25519 key followed by ML-DSA-65 key.
func (p *PublicKey) Bytes() []byte {
	return append(append([]byte{}, p.ed...), p.ml.Bytes()...)
}

func (p *PublicKey) String() string {
	return PublicPrefix + b64.EncodeToString(p.Bytes())
}

// Fingerprint is a short, stable identifier for the key, suitable for
// comparing out of band: SHA-256 of the raw key, first 16 bytes, in hex
// groups of four.
func (p *PublicKey) Fingerprint() string {
	sum := sha256.Sum256(p.Bytes())
	h := hex.EncodeToString(sum[:16])
	var b strings.Builder
	for i := 0; i < len(h); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(h[i : i+4])
	}
	return b.String()
}

// Equal reports whether p and q are the same key.
func (p *PublicKey) Equal(q *PublicKey) bool {
	return q != nil && subtle.ConstantTimeCompare(p.Bytes(), q.Bytes()) == 1
}

// ErrBadSignature is returned when either half of a signature fails.
var ErrBadSignature = errors.New("signature is not valid")

// Verify checks a hybrid signature. Both halves must verify.
func (p *PublicKey) Verify(msg, sig []byte) error {
	if len(sig) != SignatureSize {
		return fmt.Errorf("%w: wrong length", ErrBadSignature)
	}
	edOK := ed25519.Verify(p.ed, msg, sig[:ed25519.SignatureSize])
	mlErr := mldsa.Verify(p.ml, msg, sig[ed25519.SignatureSize:], &mldsa.Options{Context: mldsaContext})
	if !edOK || mlErr != nil {
		return ErrBadSignature
	}
	return nil
}
