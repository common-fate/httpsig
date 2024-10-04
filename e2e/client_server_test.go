package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/common-fate/httpsig"
	"github.com/common-fate/httpsig/alg_ecdsa"
	"github.com/common-fate/httpsig/inmemory"
)

type userAttributes struct {
	Username string
}

func TestE2E(t *testing.T) {

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key error: %s", err)
	}

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)

	verifier := httpsig.Middleware(httpsig.MiddlewareOpts{
		NonceStorage: inmemory.NewNonceStorage(),
		KeyDirectory: alg_ecdsa.StaticKeyDirectory{
			Key: &key.PublicKey,
			Attributes: userAttributes{
				Username: "Alice",
			},
		},
		Tag:       "foo",
		Scheme:    "http",
		Authority: strings.TrimPrefix(server.URL, "http://"),
		OnValidationError: func(ctx context.Context, err error) {
			fmt.Printf("validation error: %s\n", err)
		},
		OnDeriveSigningString: func(ctx context.Context, stringToSign string) {
			fmt.Printf("string to sign:\n%s\n\n", stringToSign)
		},
	})

	mux.Handle("/", verifier(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attr := httpsig.AttributesFromContext(r.Context()).(userAttributes)
		msg := fmt.Sprintf("hello, %s!", attr.Username)
		_, _ = w.Write([]byte(msg))
	})))

	defer server.Close()

	client := httpsig.NewClient(httpsig.ClientOpts{
		Tag: "foo",
		Alg: alg_ecdsa.NewP256Signer(key),
		OnDeriveSigningString: func(ctx context.Context, stringToSign string) {
			fmt.Printf("string to sign:\n%s\n\n", stringToSign)
		},
	})

	testcases := []struct {
		name    string
		req     *http.Request
		want    string
		wantErr error
	}{
		{
			"POST",
			func() *http.Request {
				req, _ := http.NewRequest(http.MethodPost, server.URL, nil)
				req.Header.Set("Content-Type", "application/json")
				return req
			}(),
			"hello, Alice!",
			nil,
		},
		{
			"GET",
			func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
				req.Header.Set("Content-Type", "application/json")
				return req
			}(),
			"hello, Alice!",
			nil,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := client.Do(tc.req)
			if err != nil {
				t.Fatalf("client post error: %v", err)
			}

			got, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("error reading response body: %v", err)
			}
			if !bytes.Equal(got, []byte(tc.want)) {
				t.Fatalf("response not as expected: got %s, wanted %s", got, tc.want)
			}
		})
	}

}
