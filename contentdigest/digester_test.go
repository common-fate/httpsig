package contentdigest

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
)

type mockReader struct {
	N   int
	Err error
}

func (r mockReader) Read(p []byte) (n int, err error) {
	return r.N, r.Err
}

func TestDigester_HashRequest(t *testing.T) {
	type testcase struct {
		name     string
		digester Digester
		req      io.ReadCloser
		wantErr  bool
		want     string
	}
	testcases := []testcase{
		// example values taken from https://www.rfc-editor.org/rfc/rfc9530.html#appendix-D
		{
			name:     "sha256",
			digester: SHA256,
			req:      io.NopCloser(bytes.NewBufferString(`{"hello": "world"}`)),
			want:     `sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:`,
		},
		{
			name:     "sha512",
			digester: SHA512,
			req:      io.NopCloser(bytes.NewBufferString(`{"hello": "world"}`)),
			want:     `sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:`,
		},
		{
			name:     "sha256_of_nil_body",
			digester: SHA256,
			req:      nil,
			want:     `sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:`,
		},
		{
			name:     "sha256_of_http_no_body",
			digester: SHA256,
			req:      http.NoBody,
			want:     `sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:`,
		},
		{
			name:     "sha256_of_empty_string",
			digester: SHA256,
			req:      io.NopCloser(bytes.NewBufferString("")),
			want:     `sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:`,
		},
		{
			name: "empty_key_returns_error",
			digester: Digester{
				HashFunc: sha256.New,
			},
			wantErr: true,
		},
		{
			name: "nil_hash_func_returns_error",
			digester: Digester{
				Key: "test",
			},
			wantErr: true,
		},
		{
			name:     "read_error_is_propagated",
			digester: SHA256,
			req:      io.NopCloser(mockReader{Err: errors.New("read error")}),
			wantErr:  true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			req := http.Request{
				Body: tc.req,
			}

			got, err := tc.digester.HashRequest(nil, &req)
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
