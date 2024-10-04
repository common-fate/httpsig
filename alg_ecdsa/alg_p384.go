package alg_ecdsa

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"

	"github.com/common-fate/httpsig/contentdigest"
)

const P384_SHA384 = `ecdsa-p384-sha384`

// NewP384Signer returns a signing algorithm based on
// the provided ecdsa private key.
func NewP384Signer(key *ecdsa.PrivateKey) *P384 {
	return &P384{PrivateKey: key}
}

// NewP384Verifier returns a verification algorithm based on
// the provided ecdsa public key.
func NewP384Verifier(key *ecdsa.PublicKey) *P384 {
	return &P384{PublicKey: key}
}

type P384 struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
	Attrs      any
}

// Attributes returns server-side attributes associated with the key.
func (a P384) Attributes() any {
	return a.Attrs
}

func (a P384) Type() string {
	return P384_SHA384
}

func (a P384) ContentDigest() contentdigest.Digester {
	return contentdigest.SHA384
}

func (a P384) Sign(ctx context.Context, base string) ([]byte, error) {
	if a.PrivateKey == nil {
		return nil, errors.New("private key was nil")
	}
	digest := sha512.New384().Sum([]byte(base))

	r, s, err := ecdsa.Sign(rand.Reader, a.PrivateKey, digest[:])
	if err != nil {
		return nil, err
	}

	// The signature algorithm returns two integer values: r and s.
	// These are both encoded as big-endian unsigned integers, zero-padded to 58 octets each.
	// These encoded values are concatenated into a single 96-octet array consisting of the
	// encoded value of r followed by the encoded value of s.
	//
	// The resulting concatenation of (r, s) is a byte array of the HTTP message signature output used in Section 3.1.
	sigBytes := make([]byte, 96)
	r.FillBytes(sigBytes[0:48])
	s.FillBytes(sigBytes[48:96])

	return sigBytes, nil
}

func (a P384) Verify(ctx context.Context, base string, signature []byte) error {
	if len(signature) != 96 {
		return fmt.Errorf("expected 96 byte signature but got %v bytes", len(signature))
	}

	digest := sha512.New384().Sum([]byte(base))

	// The signature algorithm returns two integer values: r and s.
	// These are both encoded as big-endian unsigned integers, zero-padded to 48 octets each.
	// These encoded values are concatenated into a single 96-octet array consisting of the
	// encoded value of r followed by the encoded value of s.
	//
	// The resulting concatenation of (r, s) is a byte array of the HTTP message signature output used in Section 3.1.
	r := new(big.Int)
	r.SetBytes(signature[0:48])

	s := new(big.Int)
	s.SetBytes(signature[48:96])

	valid := ecdsa.Verify(a.PublicKey, digest[:], r, s)

	if !valid {
		return errors.New("invalid signature")
	}

	return nil
}
