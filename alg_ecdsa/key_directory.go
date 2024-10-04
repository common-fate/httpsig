package alg_ecdsa

import (
	"context"
	"crypto/ecdsa"

	"github.com/common-fate/httpsig/verifier"
)

// StaticKeyDirectory implements the verifier.KeyDirectory interface
// for ECDSA P256 keys.
// It returns a static key regardless of the provided Key ID argument.
type StaticKeyDirectory struct {
	Key        *ecdsa.PublicKey
	Attributes any
}

func (d StaticKeyDirectory) GetKey(ctx context.Context, _ string, _ string) (verifier.Algorithm, error) {
	alg := P256{
		PublicKey: d.Key,
		Attrs:     d.Attributes,
	}
	return alg, nil
}

// P384StaticKeyDirectory implements the verifier.KeyDirectory interface
// for ECDSA P384 keys.
// It returns a static key regardless of the provided Key ID argument.
type P384StaticKeyDirectory struct {
	Key        *ecdsa.PublicKey
	Attributes any
}

func (d P384StaticKeyDirectory) GetKey(ctx context.Context, _ string, _ string) (verifier.Algorithm, error) {
	alg := P384{
		PublicKey: d.Key,
		Attrs:     d.Attributes,
	}
	return alg, nil
}
