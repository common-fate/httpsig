package alg_rsa

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestRSAPSS512SignVerify(t *testing.T) {
	kp, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name          string
		base          string
		privateKey    *rsa.PrivateKey
		publicKey     *rsa.PublicKey
		wantSignErr   bool
		wantVerifyErr bool
	}{
		{
			name:          "Valid key",
			base:          "signed base",
			privateKey:    kp,
			publicKey:     &kp.PublicKey,
			wantSignErr:   false,
			wantVerifyErr: false,
		},
		{
			name:        "nil private key",
			base:        "signed base",
			privateKey:  nil,
			wantSignErr: true,
		},
		{
			name:          "nil public key",
			base:          "signed base",
			privateKey:    kp,
			publicKey:     nil,
			wantSignErr:   false,
			wantVerifyErr: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rsaSigner := RSAPSS512{PrivateKey: tc.privateKey, PublicKey: tc.publicKey}
			got, err := rsaSigner.Sign(context.Background(), tc.base)
			if err != nil {
				if !tc.wantSignErr {
					t.Error(err)
				}
				return
			}
			if tc.wantSignErr {
				t.Errorf("wanted error, got none")
				return
			}

			err = rsaSigner.Verify(context.Background(), tc.base, got)
			if err != nil {
				if !tc.wantVerifyErr {
					t.Error(err)
				}
				return
			}
			if tc.wantVerifyErr {
				t.Errorf("wanted error, got none")
				return
			}
		})
	}
}
