package sigbase

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/common-fate/httpsig/contentdigest"
	"github.com/common-fate/httpsig/sigparams"
	"github.com/google/go-cmp/cmp"
)

func TestDerive(t *testing.T) {
	type testcase struct {
		name     string
		params   sigparams.Params
		digester contentdigest.Digester
		req      func() (*http.Request, error)
		wantErr  bool
		want     *Base
	}
	testcases := []testcase{
		{
			name: "ok",
			params: sigparams.Params{
				CoveredComponents: []string{"@method", "@target-uri"},
			},
			req: func() (*http.Request, error) {
				return http.NewRequest("POST", "https://example.com", nil)
			},
			want: &Base{
				Values: map[string]string{
					"@method":     "POST",
					"@target-uri": "https://example.com/",
				},
				Header: http.Header{},
			},
		},
		{
			name: "with_headers",
			params: sigparams.Params{
				CoveredComponents: []string{"@method", "@target-uri", "content-type"},
				KeyID:             "testkey-123",
				Alg:               "ecdsa-p256-sha256",
				Tag:               "example-app",
				Created:           time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
			},
			req: func() (*http.Request, error) {
				req, err := http.NewRequest("POST", "https://example.com", nil)
				if err != nil {
					return nil, err
				}
				req.Header.Add("Content-Type", "application/json")
				return req, nil
			},
			want: &Base{
				Values: map[string]string{
					"@method":      "POST",
					"@target-uri":  "https://example.com/",
					"content-type": "application/json",
				},
				Header: http.Header{
					"Content-Type": {"application/json"},
				},
			},
		},
		{
			name: "with_content_length",
			params: sigparams.Params{
				CoveredComponents: []string{"content-length"},
				KeyID:             "testkey-123",
				Alg:               "ecdsa-p256-sha256",
				Tag:               "example-app",
				Created:           time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
			},

			req: func() (*http.Request, error) {
				return http.NewRequest("POST", "https://example.com", bytes.NewBufferString("hello"))
			},
			want: &Base{
				Values: map[string]string{
					"content-length": "5",
				},
				Header: http.Header{},
			},
		},
		{
			name: "with_content_digest",
			params: sigparams.Params{
				CoveredComponents: []string{"content-digest"},
				Created:           time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
			},
			digester: contentdigest.SHA256,
			req: func() (*http.Request, error) {
				return http.NewRequest("POST", "https://example.com", bytes.NewBufferString("hello"))
			},
			want: &Base{
				Values: map[string]string{
					"content-digest": "sha-256=:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=:",
				},
				Header: http.Header{},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {

			req, err := tc.req()
			if err != nil {
				t.Fatalf("error constructing test HTTP request: %s", err)
			}

			got, err := Derive(tc.params, nil, req, tc.digester)
			if (err != nil) != tc.wantErr {
				t.Fatalf("wantErr = %v, err = %s", tc.wantErr, err)
			}

			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Errorf("deriveSignatureBase() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
