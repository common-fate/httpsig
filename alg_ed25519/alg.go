package alg_ed25519

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/common-fate/httpsig"
	"github.com/common-fate/httpsig/contentdigest"
	"github.com/common-fate/httpsig/signer"
	"github.com/common-fate/httpsig/verifier"
)

const Ed25519Alg = "ed25519"

type Ed25519 struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	Attrs      any
}

var _ verifier.Algorithm = &Ed25519{}
var _ signer.Algorithm = &Ed25519{}
var _ httpsig.Attributer = &Ed25519{}

func (a Ed25519) Attributes() any {
	return a.Attrs
}

func (a Ed25519) Type() string {
	return Ed25519Alg
}

func (a Ed25519) ContentDigest() contentdigest.Digester {
	return contentdigest.SHA512
}

func (a Ed25519) Sign(ctx context.Context, base string) ([]byte, error) {
	if a.PrivateKey == nil {
		return nil, errors.New("private key was nil")
	}
	return ed25519.Sign(a.PrivateKey, []byte(base)), nil
}

func (a Ed25519) Verify(ctx context.Context, base string, sig []byte) error {
	if a.PublicKey == nil {
		return errors.New("public key was nil")
	}
	if !ed25519.Verify(a.PublicKey, []byte(base), sig) {
		return errors.New("signature verification failed")
	}
	return nil
}
