package ascii

import (
	"testing"
)

func TestWriter_WriteString(t *testing.T) {
	type testcase struct {
		name    string
		give    string
		want    int
		wantErr bool
	}
	testcases := []testcase{
		{
			name: "ok",
			give: "test",
			want: 4,
		},
		{
			name:    "non_ascii",
			give:    "😡",
			wantErr: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			w := Writer{}

			got, err := w.WriteString(tc.give)
			if (err != nil) != tc.wantErr {
				t.Fatalf("wantErr = %v, err = %s", tc.wantErr, err)
			}
			if got != tc.want {
				t.Fatalf("want = %v, got = %v", tc.want, got)
			}
		})
	}
}

func TestWriter_Write(t *testing.T) {
	type testcase struct {
		name    string
		give    string
		want    int
		wantErr bool
	}
	testcases := []testcase{
		{
			name: "ok",
			give: "test",
			want: 4,
		},
		{
			name:    "non_ascii",
			give:    "😡",
			wantErr: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			w := Writer{}

			got, err := w.Write([]byte(tc.give))
			if (err != nil) != tc.wantErr {
				t.Fatalf("wantErr = %v, err = %s", tc.wantErr, err)
			}
			if got != tc.want {
				t.Fatalf("want = %v, got = %v", tc.want, got)
			}
		})
	}
}

func TestWriter_String(t *testing.T) {
	type testcase struct {
		name string
		give string
	}
	testcases := []testcase{
		{
			name: "ok",
			give: "test",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			w := Writer{}

			w.output.WriteString(tc.give)

			got := w.String()
			if got != tc.give {
				t.Fatalf("want = %v, got = %v", tc.give, got)
			}
		})
	}
}
