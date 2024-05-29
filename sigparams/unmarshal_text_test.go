package sigparams

import (
	"testing"
	"time"

	"github.com/dunglas/httpsfv"
	"github.com/google/go-cmp/cmp"
)

func TestParams_UnmarshalInnerList(t *testing.T) {

	tests := []struct {
		name    string
		want    Params
		input   string
		wantErr bool
	}{
		{
			name:  "ok",
			input: `("@method" "@target-uri");keyid="testkey-123";alg="ecdsa-p256-sha256";tag="foo";created=1704254706`,
			want: Params{
				KeyID:             "testkey-123",
				Tag:               "foo",
				Alg:               "ecdsa-p256-sha256",
				CoveredComponents: []string{"@method", "@target-uri"},
				Created:           time.Date(2024, 01, 03, 04, 05, 06, 00, time.FixedZone("GMT", 0)),
			},
		},
		{
			name:  "empty covered components",
			input: `();keyid="testkey-123";alg="ecdsa-p256-sha256";tag="foo";created=1704254706`,
			want: Params{
				KeyID:   "testkey-123",
				Tag:     "foo",
				Alg:     "ecdsa-p256-sha256",
				Created: time.Date(2024, 01, 03, 04, 05, 06, 00, time.FixedZone("GMT", 0)),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, err := httpsfv.UnmarshalList([]string{tt.input})
			if err != nil {
				t.Fatalf("unmarshalling list: %s", err)
			}
			il := l[0].(httpsfv.InnerList)

			p, err := UnmarshalInnerList(il)
			if (err != nil) != tt.wantErr {
				t.Errorf("Params.UnmarshalInnerList() error = %v, wantErr %v", err, tt.wantErr)
			}

			if diff := cmp.Diff(p, &tt.want); diff != "" {
				t.Errorf("Params.UnmarshalInnerList() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
