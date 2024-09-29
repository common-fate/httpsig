/*
This package contains a main for a simple client that sends a POST request to a
server that requires a signature using ecdsa-p256-sha256.
*/
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http/httputil"

	"github.com/common-fate/httpsig"
	"github.com/common-fate/httpsig/alg_ecdsa"
)

func main() {
	// Example key for testing purposes only, do not use in production
	keyString := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFKbhfNZfpDsW43+0+JjUr9K+bTeuxopu653+hBaXGA7oAoGCCqGSM49
AwEHoUQDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lfw0EkjqF7xB4FivAxzic30tMM
4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END EC PRIVATE KEY-----
`

	block, _ := pem.Decode([]byte(keyString))

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	client := httpsig.NewClient(httpsig.ClientOpts{
		Tag: "foo",
		Alg: alg_ecdsa.NewP256Signer(key),
		OnDeriveSigningString: func(ctx context.Context, stringToSign string) {
			fmt.Printf("string to sign:\n%s\n\n", stringToSign)
		},
	})

	res, err := client.Post("http://localhost:9091", "application/json", nil)
	if err != nil {
		log.Fatal(err)
	}

	resBytes, err := httputil.DumpResponse(res, true)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(resBytes))
}
