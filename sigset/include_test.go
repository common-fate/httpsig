package sigset

import (
	"net/http"
	"testing"
	"time"

	"github.com/common-fate/httpsig/signature"
	"github.com/common-fate/httpsig/sigparams"
	"github.com/google/go-cmp/cmp"
)

// TestMessage_Include tests that we can roundtrip to/from
// the HTTP request headers.
func TestMessage_Include(t *testing.T) {
	type testcase struct {
		name string
		set  Set
	}
	testcases := []testcase{
		{
			name: "ok",
			set: Set{
				Messages: map[string]*signature.Message{
					"sig1": {
						Input: sigparams.Params{
							CoveredComponents: []string{"@method", "@target-uri"},
							KeyID:             "testkey-123",
							Alg:               "ecdsa-p256-sha256",
							Tag:               "example-app",
							Created:           time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
						},
						Signature: []byte("MOCK_SIGNATURE"),
					},
				},
			},
		},
		{
			name: "multiple",
			set: Set{
				Messages: map[string]*signature.Message{
					"sig1": {
						Input: sigparams.Params{
							CoveredComponents: []string{"@method", "@target-uri"},
							KeyID:             "testkey-123",
							Alg:               "ecdsa-p256-sha256",
							Tag:               "example-app",
							Created:           time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
						},
						Signature: []byte("MOCK_SIGNATURE"),
					},
					"sig2": {
						Input: sigparams.Params{
							CoveredComponents: []string{"@method", "@target-uri"},
							KeyID:             "testkey-123",
							Created:           time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
						},
						Signature: []byte("SECOND"),
					},
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {

			req, err := http.NewRequest("POST", "https://example.com", nil)
			if err != nil {
				t.Fatalf("error constructing test HTTP request: %s", err)
			}

			err = tc.set.Include(req)
			if err != nil {
				t.Fatalf("err = %s", err)
			}

			got, err := Unmarshal(req)
			if err != nil {
				t.Fatalf("unmarshal error: %s", err)
			}

			if diff := cmp.Diff(&tc.set, got); diff != "" {
				t.Errorf("verifier.Parse() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
