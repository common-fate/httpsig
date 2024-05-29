package sigbase

import (
	"net/http"
	"testing"

	"github.com/common-fate/httpsig/contentdigest"
)

func Test_getComponentValue(t *testing.T) {
	type args struct {
		identifier string
		r          func() *http.Request
		digester   contentdigest.Digester
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "ok",
			args: args{
				identifier: "@method",
				r: func() *http.Request {
					req, _ := http.NewRequest("POST", "https://example.com", nil)
					return req
				},
			},
			want: "POST",
		},
		{
			name: "target_uri",
			args: args{
				identifier: "@target-uri",
				r: func() *http.Request {
					req, _ := http.NewRequest("POST", "https://example.com", nil)
					return req
				},
			},
			want: "https://example.com/",
		},
		{
			name: "scheme",
			args: args{
				identifier: "@scheme",
				r: func() *http.Request {
					req, _ := http.NewRequest("POST", "https://example.com", nil)
					return req
				},
			},
			want: "https",
		},
		{
			name: "authority",
			args: args{
				identifier: "@authority",
				r: func() *http.Request {
					req, _ := http.NewRequest("POST", "https://example.com", nil)
					return req
				},
			},
			want: "example.com",
		},
		{
			name: "header_value",
			args: args{
				identifier: "my-header",
				r: func() *http.Request {
					req, _ := http.NewRequest("POST", "https://example.com", nil)
					req.Header.Add("my-header", "test")
					return req
				},
			},
			want: "test",
		},
		{
			name: "uppercase",
			args: args{
				identifier: "My-Header",
				r: func() *http.Request {
					req, _ := http.NewRequest("POST", "https://example.com", nil)
					req.Header.Add("my-header", "test")
					return req
				},
			},
			wantErr: true,
		},
		{
			name: "multiple_header_values",
			args: args{
				identifier: "cache-control",
				r: func() *http.Request {
					req, _ := http.NewRequest("POST", "https://example.com", nil)
					req.Header.Add("Cache-Control", "max-age=60")
					req.Header.Add("Cache-Control", "  must-revalidate")
					return req
				},
			},
			want: "max-age=60, must-revalidate",
		},
		{
			name: "obsolete_line_folding_is_removed",
			args: args{
				identifier: "x-obs-fold-header",
				r: func() *http.Request {
					req, _ := http.NewRequest("POST", "https://example.com", nil)
					req.Header.Add("X-Obs-Fold-Header", `Obsolete
  line folding.`)
					return req
				},
			},
			want: "Obsolete line folding.",
		},
		{
			name: "obsolete_line_folding_is_removed_with_spaces",
			args: args{
				identifier: "x-obs-fold-header",
				r: func() *http.Request {
					req, _ := http.NewRequest("POST", "https://example.com", nil)
					req.Header.Add("X-Obs-Fold-Header", "Obsolete   \n  \n\n\t    \n   line folding.")
					return req
				},
			},
			want: "Obsolete line folding.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getComponentValue(tt.args.identifier, nil, tt.args.r(), tt.args.digester)
			if (err != nil) != tt.wantErr {
				t.Errorf("getComponentValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getComponentValue() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isLower(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLower(tt.args.s); got != tt.want {
				t.Errorf("isLower() = %v, want %v", got, tt.want)
			}
		})
	}
}
