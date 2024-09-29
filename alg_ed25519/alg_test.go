package alg_ed25519

import (
	"context"
	"crypto/ed25519"
	"testing"
)

func TestSignVerify(t *testing.T) {
	ctx := context.Background()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key error: %s", err)
	}

	alg := Ed25519{
		PrivateKey: priv,
		PublicKey:  pub,
	}

	base := "example"

	sig, err := alg.Sign(ctx, base)
	if err != nil {
		t.Fatalf("sign error: %s", err)
	}

	err = alg.Verify(ctx, base, sig)
	if err != nil {
		t.Fatalf("verify error: %s", err)
	}
}
