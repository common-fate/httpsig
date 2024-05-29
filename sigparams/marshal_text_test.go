package sigparams

import (
	"testing"
	"time"
)

func TestSigner_marshalText(t *testing.T) {

	type testcase struct {
		name    string
		fields  Params
		wantErr bool
		want    string
	}
	testcases := []testcase{
		{
			name: "ok",
			fields: Params{
				KeyID:   "testkey-123",
				Alg:     "ecdsa-p256-sha256",
				Tag:     "example-app",
				Created: time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
			},
			want: `();keyid="testkey-123";alg="ecdsa-p256-sha256";tag="example-app";created=1704254706`,
		},
		{
			name: "with_no_alg",
			fields: Params{
				KeyID:   "testkey-123",
				Tag:     "example-app",
				Created: time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
			},
			want: `();keyid="testkey-123";tag="example-app";created=1704254706`,
		},
		{
			name: "with_covered_components",
			fields: Params{
				CoveredComponents: []string{"@method", "@target-uri"},
				KeyID:             "testkey-123",
				Alg:               "ecdsa-p256-sha256",
				Tag:               "example-app",
				Created:           time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
			},
			want: `("@method" "@target-uri");keyid="testkey-123";alg="ecdsa-p256-sha256";tag="example-app";created=1704254706`,
		},
		{
			name: "with_nonce",
			fields: Params{
				CoveredComponents: []string{"@method", "@target-uri"},
				KeyID:             "testkey-123",
				Alg:               "ecdsa-p256-sha256",
				Nonce:             "12345abcdef",
				Tag:               "example-app",
				Created:           time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
			},
			want: `("@method" "@target-uri");keyid="testkey-123";alg="ecdsa-p256-sha256";tag="example-app";nonce="12345abcdef";created=1704254706`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.fields.MarshalText()
			if (err != nil) != tc.wantErr {
				t.Fatalf("wantErr = %v, err = %s", tc.wantErr, err)
			}

			if string(got) != tc.want {
				t.Fatalf("want = %s, got = %s", tc.want, got)
			}
		})
	}
}
