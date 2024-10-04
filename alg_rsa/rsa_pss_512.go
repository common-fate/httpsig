package alg_rsa

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"errors"

	"github.com/common-fate/httpsig/contentdigest"
)

const RSASSA_PSS_SHA512 = `rsa-pss-sha512`

// NewRSAPSS512Signer returns a signing algorithm based on
// the provided rsa private key.
func NewRSAPSS512Signer(key *rsa.PrivateKey) *RSAPSS512 {
	return &RSAPSS512{PrivateKey: key, PublicKey: &key.PublicKey}
}

// NewRSAPSS512Verifier returns a verification algorithm based on
// the provided rsa public key.
func NewRSAPSS512Verifier(key *rsa.PublicKey) *RSAPSS512 {
	return &RSAPSS512{PublicKey: key}
}

type RSAPSS512 struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Attrs      any
}

// Attributes returns server-side attributes associated with the key.
func (a RSAPSS512) Attributes() any {
	return a.Attrs
}

func (a RSAPSS512) Type() string {
	return RSASSA_PSS_SHA512
}

func (a RSAPSS512) ContentDigest() contentdigest.Digester {
	return contentdigest.SHA512
}

func (a RSAPSS512) Sign(ctx context.Context, base string) ([]byte, error) {
	if a.PrivateKey == nil {
		return nil, errors.New("private key was nil")
	}
	digest := sha512.Sum512([]byte(base))
	return rsa.SignPSS(rand.Reader, a.PrivateKey, crypto.SHA512, digest[:], &rsa.PSSOptions{
		SaltLength: 64,
	})
}

func (a RSAPSS512) Verify(ctx context.Context, base string, signature []byte) error {
	if a.PublicKey == nil {
		return errors.New("public key was nil")
	}
	digest := sha512.Sum512([]byte(base))
	return rsa.VerifyPSS(a.PublicKey, crypto.SHA512, digest[:], signature, &rsa.PSSOptions{
		SaltLength: 64,
	})
}
