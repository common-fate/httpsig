package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"

	"github.com/common-fate/httpsig"
	"github.com/common-fate/httpsig/alg_ecdsa"
	"github.com/common-fate/httpsig/inmemory"
)

func main() {
	keyString := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lf
w0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END PUBLIC KEY-----
`

	block, _ := pem.Decode([]byte(keyString))

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	ecKey := key.(*ecdsa.PublicKey)

	mux := http.NewServeMux()

	verifier := httpsig.Middleware(httpsig.MiddlewareOpts{
		NonceStorage: inmemory.NewNonceStorage(),
		KeyDirectory: alg_ecdsa.StaticKeyDirectory{
			Key: ecKey,
			Attributes: exampleAttributes{
				Username: "Alice",
			},
		},
		Tag:       "foo",
		Scheme:    "http",
		Authority: "localhost:9091",

		OnValidationError: func(ctx context.Context, err error) {
			fmt.Printf("validation error: %s\n", err)
		},

		OnDeriveSigningString: func(ctx context.Context, stringToSign string) {
			fmt.Printf("string to sign:\n%s\n\n", stringToSign)
		},
	})

	mux.Handle("/", verifier(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attr := httpsig.AttributesFromContext(r.Context()).(exampleAttributes)
		msg := fmt.Sprintf("hello, %s!", attr.Username)
		w.Write([]byte(msg))
	})))

	err = http.ListenAndServe("localhost:9091", mux)
	if err != nil {
		log.Fatal(err)
	}
}

type exampleAttributes struct {
	Username string
}
