package alg_ed25519

import (
	"context"
	"crypto/ed25519"

	"github.com/common-fate/httpsig/verifier"
)

// SingleKeyDirectory implements the verifier.KeyDirectory interface.
// It returns a static key regardless of the provided Key ID argument.
type SingleKeyDirectory struct {
	Key        ed25519.PublicKey
	Attributes any
}

func (d SingleKeyDirectory) GetKey(ctx context.Context, _ string, _ string) (verifier.Algorithm, error) {
	alg := Ed25519{
		PublicKey: d.Key,
		Attrs:     d.Attributes,
	}
	return alg, nil
}
