# httpsig

[![Go Reference](https://pkg.go.dev/badge/github.com/common-fate/httpsig.svg)](https://pkg.go.dev/github.com/common-fate/httpsig)

An implementation of [RFC9421: HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html) in Go.

This library has support for the following features:

- Pluggable algorithms for signing and verification.

- Support for creating a signed [`content-digest` field](https://www.rfc-editor.org/info/rfc9530) to protect the HTTP request body.

- Protection against resource exhaustion when verifying the `content-digest` field.

- Support for multiple HTTP request signatures.

- Pluggable key directory for key material lookup.

- Pluggable nonce storage backends to protect against replay attacks.

- Safe-by-default middleware which strips unsigned HTTP headers and prevents unsigned HTTP request bodies from being read.

- Client and server-side hooks to debug signing errors.

- Support for server-side attributes associated with signing keys (see below for an example).

## Usage

### Client

```go
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http/httputil"

	"github.com/common-fate/httpsig"
	"github.com/common-fate/httpsig/alg_ecdsa"
)

func main() {
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
```

### Server

```go
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
```
