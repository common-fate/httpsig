package sigparams

import (
	"testing"
	"time"
)

func TestParams_Validate(t *testing.T) {
	type fields struct {
		KeyID             string
		Tag               string
		Alg               string
		CoveredComponents []string
		Nonce             string
		Created           time.Time
		Expires           time.Time
	}
	tests := []struct {
		name    string
		fields  fields
		now     time.Time
		args    ValidateOpts
		wantErr bool
	}{
		{
			name: "ok",
			fields: fields{
				Created: time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
				// CoveredComponents: []string{"@method", "@target-uri"},
			},
			now: time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
			args: ValidateOpts{
				BeforeDuration: time.Minute,
			},
		},
		{
			name: "covered_components",
			fields: fields{
				Created:           time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
				CoveredComponents: []string{"@method", "@target-uri"},
			},
			now: time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
			args: ValidateOpts{
				RequiredCoveredComponents: map[string]bool{
					"@method":     true,
					"@target-uri": true,
				},
			},
		},
		{
			name: "covered_components_failure",
			fields: fields{
				Created:           time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
				CoveredComponents: []string{"@method"},
			},
			now: time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
			args: ValidateOpts{
				RequiredCoveredComponents: map[string]bool{
					"@method":     true,
					"@target-uri": true,
				},
			},
			wantErr: true,
		},
		{
			name:   "nonce_required",
			fields: fields{},
			args: ValidateOpts{
				RequireNonce: true,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Params{
				KeyID:             tt.fields.KeyID,
				Tag:               tt.fields.Tag,
				Alg:               tt.fields.Alg,
				CoveredComponents: tt.fields.CoveredComponents,
				Nonce:             tt.fields.Nonce,
				Created:           tt.fields.Created,
				Expires:           tt.fields.Expires,
			}
			if err := p.Validate(tt.args, tt.now); (err != nil) != tt.wantErr {
				t.Errorf("Params.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
