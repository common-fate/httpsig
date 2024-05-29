package verifier

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/common-fate/httpsig/contentdigest"
	"github.com/common-fate/httpsig/sigparams"
	"github.com/google/go-cmp/cmp"
)

type testNonceStorage struct {
	IsSeen bool
	Err    error
}

func (t testNonceStorage) Seen(ctx context.Context, nonce string) (bool, error) {
	return t.IsSeen, t.Err
}

type testAlgSelector struct {
	Algorithm testAlgorithm
	Err       error
}

func (t testAlgSelector) GetKey(ctx context.Context, key string, clientAlgorithmParameter string) (Algorithm, error) {
	return t.Algorithm, t.Err
}

type testAlgorithm struct {
	AlgType string
	Err     error
	Digest  contentdigest.Digester
}

func (t testAlgorithm) Type() string {
	return t.AlgType
}

func (t testAlgorithm) Verify(ctx context.Context, base string, sig []byte) error {
	return t.Err
}
func (t testAlgorithm) ContentDigest() contentdigest.Digester {
	return t.Digest
}

func TestVerifier_Parse(t *testing.T) {
	type fields struct {
		NonceStorage NonceStorage
		KeyDirectory KeyDirectory
		Tag          string
		Validation   sigparams.ValidateOpts
		Authority    string
		Scheme       string
	}
	type args struct {
		req func() *http.Request
	}
	tests := []struct {
		name            string
		fields          fields
		req             func() *http.Request
		wantHeaders     http.Header
		now             time.Time
		wantBodyReadErr bool
		wantBody        string
		wantErr         bool
	}{
		{
			name: "ok",
			fields: fields{
				NonceStorage: testNonceStorage{},
				KeyDirectory: testAlgSelector{
					Algorithm: testAlgorithm{
						Digest:  contentdigest.SHA256,
						AlgType: "ecdsa-p256-sha256",
					},
				},
				Tag: "example-app",
				Validation: sigparams.ValidateOpts{
					RequiredCoveredComponents: map[string]bool{
						"@target-uri": true,
						"@method":     true,
					},
					BeforeDuration: time.Minute,
				},
				Authority: "example.com",
				Scheme:    "https",
			},
			now: time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
			req: func() *http.Request {
				req, _ := http.NewRequest("POST", "https://example.com", strings.NewReader("example body"))
				req.Header.Add("Signature", `sig1=:TU9DS19TSUdOQVRVUkU=:`)
				req.Header.Add("Signature-Input", `sig1=("@method" "@target-uri" "content-digest" "content-length");keyid="testkey-123";alg="ecdsa-p256-sha256";tag="example-app";created=1704254706`)

				return req
			},
			wantBody:    "example body",
			wantHeaders: http.Header{},
		},

		{
			name: "with_headers",
			fields: fields{
				NonceStorage: testNonceStorage{},
				KeyDirectory: testAlgSelector{
					Algorithm: testAlgorithm{
						Digest:  contentdigest.SHA256,
						AlgType: "ecdsa-p256-sha256",
					},
				},
				Tag: "example-app",
				Validation: sigparams.ValidateOpts{
					RequiredCoveredComponents: map[string]bool{
						"@target-uri": true,
						"@method":     true,
					},
				},
				Authority: "example.com",
				Scheme:    "https",
			},
			now: time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
			req: func() *http.Request {
				req, _ := http.NewRequest("POST", "https://example.com", nil)
				req.Header.Add("Signature", `sig1=:TU9DS19TSUdOQVRVUkU=:`)
				req.Header.Add("Signature-Input", `sig1=("@method" "@target-uri" "content-type");keyid="testkey-123";alg="ecdsa-p256-sha256";tag="example-app";created=1704254706`)
				req.Header.Add("Content-Type", `application/json`)

				return req
			},
			wantBodyReadErr: true, // can't read it as it isn't covered in the signature
			wantHeaders: http.Header{
				"content-type": {"application/json"},
			},
		},

		{
			name: "fails_if_nonce_is_seen",
			fields: fields{
				NonceStorage: testNonceStorage{
					IsSeen: true,
				},
				KeyDirectory: testAlgSelector{
					Algorithm: testAlgorithm{
						Digest: contentdigest.SHA256,
					},
				},
				Tag:       "example-app",
				Authority: "example.com",
				Scheme:    "https",
			},
			now: time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
			req: func() *http.Request {
				req, _ := http.NewRequest("POST", "https://example.com", strings.NewReader(`{"hello": "world"}`))
				req.Header.Add("Signature", `sig1=:TU9DS19TSUdOQVRVUkU=:`)
				req.Header.Add("Signature-Input", `sig1=("@method" "@target-uri" "content-digest" "content-length");keyid="testkey-123";alg="ecdsa-p256-sha256";tag="example-app";created=1704254706`)

				return req
			},
			wantErr: true,
		},

		{
			name: "fails_if_nonce_storage_error",
			fields: fields{
				NonceStorage: testNonceStorage{
					Err: errors.New("nonce check error"),
				},
				KeyDirectory: testAlgSelector{
					Algorithm: testAlgorithm{
						Digest: contentdigest.SHA256,
					},
				},
				Tag:       "example-app",
				Authority: "example.com",
				Scheme:    "https",
			},
			now: time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
			req: func() *http.Request {
				req, _ := http.NewRequest("POST", "https://example.com", strings.NewReader(`{"hello": "world"}`))
				req.Header.Add("Signature", `sig1=:TU9DS19TSUdOQVRVUkU=:`)
				req.Header.Add("Signature-Input", `sig1=("@method" "@target-uri" "content-digest" "content-length");keyid="testkey-123";alg="ecdsa-p256-sha256";tag="example-app";created=1704254706`)

				return req
			},
			wantErr: true,
		},

		{
			name: "fails_if_key_directory_error",
			fields: fields{
				NonceStorage: testNonceStorage{},
				KeyDirectory: testAlgSelector{
					Err: errors.New("key error"),
				},
				Tag:       "example-app",
				Authority: "example.com",
				Scheme:    "https",
			},
			now: time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
			req: func() *http.Request {
				req, _ := http.NewRequest("POST", "https://example.com", strings.NewReader(`{"hello": "world"}`))
				req.Header.Add("Signature", `sig1=:TU9DS19TSUdOQVRVUkU=:`)
				req.Header.Add("Signature-Input", `sig1=("@method" "@target-uri" "content-digest" "content-length");keyid="testkey-123";alg="ecdsa-p256-sha256";tag="example-app";created=1704254706`)

				return req
			},
			wantErr: true,
		},

		{
			name: "fails_if_alg_verification_error",
			fields: fields{
				NonceStorage: testNonceStorage{},
				KeyDirectory: testAlgSelector{
					Algorithm: testAlgorithm{
						Err:    errors.New("verification error"),
						Digest: contentdigest.SHA256,
					},
				},
				Tag:       "example-app",
				Authority: "example.com",
				Scheme:    "https",
			},
			now: time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
			req: func() *http.Request {
				req, _ := http.NewRequest("POST", "https://example.com", strings.NewReader(`{"hello": "world"}`))
				req.Header.Add("Signature", `sig1=:TU9DS19TSUdOQVRVUkU=:`)
				req.Header.Add("Signature-Input", `sig1=("@method" "@target-uri" "content-digest" "content-length");keyid="testkey-123";alg="ecdsa-p256-sha256";tag="example-app";created=1704254706`)

				return req
			},
			wantErr: true,
		},

		{
			name: "fails_if_authority_doesnt_match",
			fields: fields{
				NonceStorage: testNonceStorage{},
				KeyDirectory: testAlgSelector{
					Algorithm: testAlgorithm{
						Digest: contentdigest.SHA256,
					},
				},
				Tag:       "example-app",
				Authority: "other.com",
			},
			now: time.Date(2024, 01, 03, 04, 05, 06, 00, time.UTC),
			req: func() *http.Request {
				req, _ := http.NewRequest("POST", "https://example.com", strings.NewReader(`{"hello": "world"}`))
				req.Header.Add("Signature", `sig1=:TU9DS19TSUdOQVRVUkU=:`)
				req.Header.Add("Signature-Input", `sig1=("@method" "@target-uri" "content-digest" "content-length");keyid="testkey-123";alg="ecdsa-p256-sha256";tag="example-app";created=1704254706`)

				return req
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Verifier{
				NonceStorage: tt.fields.NonceStorage,
				KeyDirectory: tt.fields.KeyDirectory,
				Tag:          tt.fields.Tag,
				Validation:   tt.fields.Validation,
				Scheme:       tt.fields.Scheme,
				Authority:    tt.fields.Authority,
			}
			req := tt.req()
			got, _, err := v.Parse(nil, req, tt.now)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verifier.Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			var gotBody []byte
			var gotHeaders http.Header

			if got != nil {
				gotBody, err = io.ReadAll(got.Body)
				if (err != nil) != tt.wantBodyReadErr {
					t.Errorf("read body error = %v, wantBodyReadErr %v", err, tt.wantErr)
					return
				}
				gotHeaders = got.Header
			}

			if diff := cmp.Diff(tt.wantBody, string(gotBody)); diff != "" {
				t.Errorf("read body mismatch (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(tt.wantHeaders, gotHeaders); diff != "" {
				t.Errorf("headers mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
