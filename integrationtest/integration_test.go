package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/common-fate/httpsig/alg_ecdsa"
	"github.com/common-fate/httpsig/inmemory"
	"github.com/common-fate/httpsig/signer"
	"github.com/common-fate/httpsig/sigparams"
	"github.com/common-fate/httpsig/verifier"
)

func TestECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key error: %s", err)
	}

	v := verifier.Verifier{
		NonceStorage: inmemory.NewNonceStorage(),
		KeyDirectory: alg_ecdsa.StaticKeyDirectory{
			Key: &key.PublicKey,
		},
		Tag: "foo",
		Validation: sigparams.ValidateOpts{
			RequiredCoveredComponents: map[string]bool{
				"@method": true,
			},
			BeforeDuration: 5 * time.Minute,
			RequireNonce:   true,
		},
	}

	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		_, _, err = v.Parse(w, r, now)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(err.Error()))
		}
	}))
	defer svr.Close()

	alg := alg_ecdsa.P256{
		PrivateKey: key,
		PublicKey:  &key.PublicKey,
	}

	client := svr.Client()

	client.Transport = &signer.Transport{
		KeyID:             "123",
		Tag:               "foo",
		Alg:               alg,
		CoveredComponents: []string{"@method"},
		BaseTransport:     client.Transport,
	}

	req, err := http.NewRequest("POST", svr.URL, strings.NewReader(`{"hello": "world"}`))
	if err != nil {
		t.Fatalf("error creating request: %s", err)
	}

	req.Host = "https://example.com"

	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTP send error: %s", err)
	}

	if res.StatusCode != 200 {
		defer res.Body.Close()
		bodyBytes, _ := io.ReadAll(res.Body)

		t.Fatalf("got status %v: %s", res.StatusCode, bodyBytes)
	}
}

func TestECDSA_InvalidSignature(t *testing.T) {
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key error: %s", err)
	}

	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key error: %s", err)
	}

	v := verifier.Verifier{
		NonceStorage: inmemory.NewNonceStorage(),
		KeyDirectory: alg_ecdsa.StaticKeyDirectory{
			Key: &key1.PublicKey,
		},
		Tag: "foo",
		Validation: sigparams.ValidateOpts{
			RequiredCoveredComponents: map[string]bool{
				"@method": true,
			},
			BeforeDuration: 5 * time.Minute,
			RequireNonce:   true,
		},
	}

	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		_, _, err = v.Parse(w, r, now)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(err.Error()))
		}
	}))
	defer svr.Close()

	alg := alg_ecdsa.P256{
		PrivateKey: key2,
	}

	client := svr.Client()

	client.Transport = &signer.Transport{
		KeyID:             "123",
		Tag:               "foo",
		Alg:               alg,
		CoveredComponents: []string{"@method"},
		BaseTransport:     client.Transport,
	}

	req, err := http.NewRequest("POST", svr.URL, strings.NewReader(`{"hello": "world"}`))
	if err != nil {
		t.Fatalf("error creating request: %s", err)
	}

	req.Host = "https://example.com"

	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTP send error: %s", err)
	}

	if res.StatusCode != 401 {
		defer res.Body.Close()
		bodyBytes, _ := io.ReadAll(res.Body)

		t.Fatalf("expected HTTP 401 but got status %v: %s", res.StatusCode, bodyBytes)
	}
}
