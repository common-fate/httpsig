package signer

import (
	"net/http"
	"testing"
	"time"

	"github.com/common-fate/httpsig/contentdigest"
	"github.com/common-fate/httpsig/signature"
	"github.com/common-fate/httpsig/sigparams"
	"github.com/google/go-cmp/cmp"
)

func TestSigner_Sign(t *testing.T) {
	type fields struct {
		coveredComponents []string
		keyID             string
		alg               Algorithm
		tag               string
		digester          contentdigest.Digester
		now               time.Time
		nonce             string
	}
	type testcase struct {
		name    string
		fields  fields
		req     func() (*http.Request, error)
		wantErr bool
		want    *signature.Message
	}
	testcases := []testcase{
		{
			name: "ok",
			fields: fields{
				coveredComponents: []string{"@method", "@target-uri"},
				keyID:             "testkey-123",
				alg: testAlgorithm{
					AlgType:   "ecdsa-p256-sha256",
					Signature: "MOCK_SIGNATURE",
				},
				tag:   "example-app",
				now:   time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
				nonce: "MOCKNONCE",
			},
			req: func() (*http.Request, error) {
				return http.NewRequest("POST", "https://example.com", nil)
			},
			want: &signature.Message{
				Input: sigparams.Params{
					KeyID:             "testkey-123",
					Tag:               "example-app",
					Alg:               "ecdsa-p256-sha256",
					CoveredComponents: []string{"@method", "@target-uri"},
					Nonce:             "MOCKNONCE",
					Created:           time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
				},
				Signature: []byte("MOCK_SIGNATURE"),
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			getCurrentTime = func() time.Time {
				return tc.fields.now
			}

			s := Transport{
				KeyID:             tc.fields.keyID,
				Tag:               tc.fields.tag,
				Alg:               tc.fields.alg,
				CoveredComponents: tc.fields.coveredComponents,
				GetNonce: func() (string, error) {
					return tc.fields.nonce, nil
				},
			}
			req, err := tc.req()
			if err != nil {
				t.Fatalf("error constructing test HTTP request: %s", err)
			}

			got, err := s.Sign(req)

			if (err != nil) != tc.wantErr {
				t.Fatalf("wantErr = %v, err = %s", tc.wantErr, err)
			}

			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Errorf("Sign() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
