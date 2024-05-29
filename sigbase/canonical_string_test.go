package sigbase

import (
	"fmt"
	"testing"
	"time"

	"github.com/common-fate/httpsig/sigparams"
)

func TestBase_CanonicalString(t *testing.T) {
	type testcase struct {
		name    string
		base    Base
		params  sigparams.Params
		wantErr bool
		want    string
	}
	testcases := []testcase{
		{
			name: "ok",
			base: Base{
				Values: map[string]string{
					"@method":     "POST",
					"@target-uri": "https://example.com",
				},
			},
			params: sigparams.Params{
				CoveredComponents: []string{"@method", "@target-uri"},
				KeyID:             "testkey-123",
				Alg:               "ecdsa-p256-sha256",
				Tag:               "example-app",
				Created:           time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
			},
			want: `"@method": POST
"@target-uri": https://example.com
"@signature-params": ("@method" "@target-uri");keyid="testkey-123";alg="ecdsa-p256-sha256";tag="example-app";created=1704254706`,
		},
		{
			name: "with_headers",
			base: Base{
				Values: map[string]string{
					"@method":      "POST",
					"@target-uri":  "https://example.com/",
					"content-type": "application/json",
				},
			},
			params: sigparams.Params{
				CoveredComponents: []string{"@method", "@target-uri", "content-type"},
				KeyID:             "testkey-123",
				Alg:               "ecdsa-p256-sha256",
				Tag:               "example-app",
				Created:           time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
			},
			want: `"@method": POST
"@target-uri": https://example.com/
"content-type": application/json
"@signature-params": ("@method" "@target-uri" "content-type");keyid="testkey-123";alg="ecdsa-p256-sha256";tag="example-app";created=1704254706`,
		},
		{
			name: "with_content_length",
			base: Base{
				Values: map[string]string{
					"content-length": "5",
				},
			},
			params: sigparams.Params{
				CoveredComponents: []string{"content-length"},
				KeyID:             "testkey-123",
				Alg:               "ecdsa-p256-sha256",
				Tag:               "example-app",
				Created:           time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
			},
			want: `"content-length": 5
"@signature-params": ("content-length");keyid="testkey-123";alg="ecdsa-p256-sha256";tag="example-app";created=1704254706`,
		},
		{
			name: "with_content_digest",
			base: Base{
				Values: map[string]string{
					"content-digest": "sha-256=:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=:",
				},
			},
			params: sigparams.Params{
				CoveredComponents: []string{"content-digest"},
				Created:           time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
			},
			want: `"content-digest": sha-256=:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=:
"@signature-params": ("content-digest");created=1704254706`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {

			got, err := tc.base.CanonicalString(tc.params)
			if (err != nil) != tc.wantErr {
				t.Fatalf("wantErr = %v, err = %s", tc.wantErr, err)
			}

			if got != tc.want {
				fmt.Printf("want:\n%s\n\n", tc.want)
				fmt.Printf("got:\n%s\n\n", got)

				t.Fatalf("want = %s, got = %s", tc.want, got)
			}
		})
	}
}
