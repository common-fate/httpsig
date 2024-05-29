package signer

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/common-fate/httpsig/contentdigest"
)

func TestTransport_nonce(t *testing.T) {
	type fields struct {
		KeyID             string
		Tag               string
		Alg               Algorithm
		CoveredComponents []string
		Digester          contentdigest.Digester
		GetNonce          func() (string, error)
		BaseTransport     http.RoundTripper
	}
	tests := []struct {
		name       string
		fields     fields
		want       string
		randReader io.Reader
		wantErr    bool
	}{
		{
			name: "ok",
			fields: fields{
				GetNonce: func() (string, error) {
					return "MOCKNONCE", nil
				},
			},
			want: "MOCKNONCE",
		},
		{
			name: "error",
			fields: fields{
				GetNonce: func() (string, error) {
					return "", errors.New("error")
				},
			},
			wantErr: true,
		},
		{
			name:       "fallback_to_random_reader",
			randReader: bytes.NewBufferString("randomrandomrandomrandomrandomrandomrandom"),
			want:       "cmFuZG9tcmFuZG9tcmFuZG9tcmFuZG9tcmFuZG9tcmE=",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldReader := rand.Reader
			defer func() {
				rand.Reader = oldReader
			}()
			rand.Reader = tt.randReader
			tr := &Transport{
				KeyID:             tt.fields.KeyID,
				Tag:               tt.fields.Tag,
				Alg:               tt.fields.Alg,
				CoveredComponents: tt.fields.CoveredComponents,
				GetNonce:          tt.fields.GetNonce,
				BaseTransport:     tt.fields.BaseTransport,
			}
			got, err := tr.nonce()
			if (err != nil) != tt.wantErr {
				t.Errorf("Transport.nonce() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Transport.nonce() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_randomNonce(t *testing.T) {
	tests := []struct {
		name       string
		wantLength int
		wantErr    bool
	}{
		{
			name:       "ok",
			wantLength: 44,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := randomNonce()
			if (err != nil) != tt.wantErr {
				t.Errorf("randomNonce() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != tt.wantLength {
				t.Errorf("len(randomNonce()) = %v, wantLength %v", len(got), tt.wantLength)
			}
		})
	}
}
