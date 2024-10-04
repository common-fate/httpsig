package alg_ecdsa

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestP384SignVerify(t *testing.T) {
	ctx := context.Background()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key error: %s", err)
	}

	alg := P384{
		PrivateKey: key,
		PublicKey:  &key.PublicKey,
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
