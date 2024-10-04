package httpsig

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/common-fate/httpsig/sigparams"
	"github.com/common-fate/httpsig/verifier"
)

type MiddlewareOpts struct {
	// NonceStorage is the storage layer
	// to check whether a nonce has been previously seen.
	NonceStorage verifier.NonceStorage

	// KeyDirectory is the directory used to look up
	// signing key material based on a key ID.
	KeyDirectory verifier.KeyDirectory

	// Tag is an application-specific tag for the signature as a String value.
	// This value is used by applications to help identify signatures relevant for specific applications or protocols.
	// See: https://www.rfc-editor.org/rfc/rfc9421.html#section-2.3-4.12
	//
	// In this verifier implementation a tag MUST be specified.
	// incoming requests must have only one signature matching the tag.
	Tag string

	// Validation overrides the validation options.
	//
	// If nil, http.DefaultValidationOpts() is used.
	Validation *sigparams.ValidateOpts

	// Scheme is the expected URL scheme
	// that the verifier is running on.
	//
	// Should be 'https' in production.
	Scheme string

	// Authority is the expected HTTP authority
	// that the verifier is running on.
	Authority string

	// OnValidationError, if set, is called when there is a validation error
	// with the request context.
	OnValidationError func(ctx context.Context, err error)

	// OnDeriveSigningString is a hook which can be used to log
	// the string to sign.
	//
	// This can be useful for debugging signature errors,
	// as you can compare the base signing string between the client
	// and server.
	OnDeriveSigningString func(ctx context.Context, stringToSign string)
}

// Attributer is an optional interface implemented by signing
// algorithms to provide additional server-side attributes
// associated with a signing key.
type Attributer interface {
	Attributes() any
}

// Middleware is an HTTP server middleware which verifies signatures
// on incoming requests.
//
// Verification of an HTTP message signature is
// a process that takes as its input the signature context
// (including the target message, particularly its Signature
// and Signature-Input fields) and the requirements for the application.
//
// See: https://www.rfc-editor.org/rfc/rfc9421.html#section-3.
func Middleware(opts MiddlewareOpts) func(next http.Handler) http.Handler {

	v := verifier.Verifier{
		NonceStorage:          opts.NonceStorage,
		KeyDirectory:          opts.KeyDirectory,
		Scheme:                opts.Scheme,
		Authority:             opts.Authority,
		Tag:                   opts.Tag,
		Validation:            DefaultValidationOpts(),
		OnDeriveSigningString: opts.OnDeriveSigningString,
	}

	if opts.Validation != nil {
		v.Validation = *opts.Validation
	}

	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			now := time.Now()
			parsedReq, key, err := v.Parse(w, r, now)
			if err != nil && opts.OnValidationError != nil {
				opts.OnValidationError(r.Context(), err)
			}

			if errors.As(err, new(*http.MaxBytesError)) {
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				_, _ = w.Write([]byte(http.StatusText(http.StatusRequestEntityTooLarge)))
				return
			}

			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
				return
			}

			if attr, ok := key.(Attributer); ok {
				attributes := attr.Attributes()
				ctx := context.WithValue(r.Context(), attributesContext, attributes)
				parsedReq = parsedReq.WithContext(ctx)
			}

			next.ServeHTTP(w, parsedReq)
		}
		return http.HandlerFunc(fn)
	}
}

// DefaultValidationOpts provides sensible default validation options.
func DefaultValidationOpts() sigparams.ValidateOpts {
	return sigparams.ValidateOpts{
		ForbidClientSideAlg: false,
		BeforeDuration:      time.Minute,
		RequiredCoveredComponents: map[string]bool{
			"@method":        true,
			"@target-uri":    true,
			"content-type":   true,
			"content-length": true,
			"content-digest": true,
		},
		RequireNonce: true,
	}
}
