package sigbase

import (
	"net/http"
	"testing"
)

func TestBase_BodyIsCovered(t *testing.T) {
	type fields struct {
		Values map[string]string
		Header http.Header
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name: "covered",
			fields: fields{
				Values: map[string]string{
					"content-digest": "foo",
					"content-length": "5",
				},
			},
			want: true,
		},
		{
			name: "uncovered",
			fields: fields{
				Values: map[string]string{},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := Base{
				Values: tt.fields.Values,
				Header: tt.fields.Header,
			}
			if got := b.BodyIsCovered(); got != tt.want {
				t.Errorf("Base.BodyIsCovered() = %v, want %v", got, tt.want)
			}
		})
	}
}
