package alg_ecdsa

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/common-fate/httpsig/contentdigest"
	"github.com/common-fate/httpsig/verifier"
)

// NewP256Signer returns a signing algorithm based on
// the provided ecdsa private key.
func NewP256Signer(key *ecdsa.PrivateKey) *P256 {
	return &P256{PrivateKey: key}
}

// NewP256Verifier returns a verification algorithm based on
// the provided ecdsa public key.
func NewP256Verifier(key *ecdsa.PublicKey) *P256 {
	return &P256{PublicKey: key}
}

type P256 struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
	Attrs      any
}

// Attributes returns server-side attributes associated with the key.
func (a P256) Attributes() any {
	return a.Attrs
}

func (a P256) Type() string {
	return "ecdsa-p256-sha256"
}

func (a P256) ContentDigest() contentdigest.Digester {
	return contentdigest.SHA256
}

func (a P256) Sign(ctx context.Context, base string) ([]byte, error) {
	if a.PrivateKey == nil {
		return nil, errors.New("private key was nil")
	}

	digest := sha256.Sum256([]byte(base))
	r, s, err := ecdsa.Sign(rand.Reader, a.PrivateKey, digest[:])
	if err != nil {
		return nil, err
	}

	// The signature algorithm returns two integer values: r and s.
	// These are both encoded as big-endian unsigned integers, zero-padded to 32 octets each.
	// These encoded values are concatenated into a single 64-octet array consisting of the
	// encoded value of r followed by the encoded value of s.
	//
	// The resulting concatenation of (r, s) is a byte array of the HTTP message signature output used in Section 3.1.
	sigBytes := make([]byte, 64)
	r.FillBytes(sigBytes[0:32])
	s.FillBytes(sigBytes[32:64])

	return sigBytes, nil
}

func (a P256) Verify(ctx context.Context, base string, signature []byte) error {
	if len(signature) != 64 {
		return fmt.Errorf("expected 64 byte signature but got %v bytes", len(signature))
	}

	digest := sha256.Sum256([]byte(base))

	// The signature algorithm returns two integer values: r and s.
	// These are both encoded as big-endian unsigned integers, zero-padded to 32 octets each.
	// These encoded values are concatenated into a single 64-octet array consisting of the
	// encoded value of r followed by the encoded value of s.
	//
	// The resulting concatenation of (r, s) is a byte array of the HTTP message signature output used in Section 3.1.
	r := new(big.Int)
	r.SetBytes(signature[0:32])

	s := new(big.Int)
	s.SetBytes(signature[32:64])

	valid := ecdsa.Verify(a.PublicKey, digest[:], r, s)

	if !valid {
		return errors.New("invalid signature")
	}

	return nil
}

// StaticKeyDirectory implements the verifier.KeyDirectory interface.
// It returns a static key regardless of the provided Key ID argument.
type StaticKeyDirectory struct {
	Key        *ecdsa.PublicKey
	Attributes any
}

func (d StaticKeyDirectory) GetKey(ctx context.Context, kid string, _ string) (verifier.Algorithm, error) {
	alg := P256{
		PublicKey: d.Key,
		Attrs:     d.Attributes,
	}
	return alg, nil
}
