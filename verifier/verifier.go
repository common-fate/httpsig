package verifier

import (
	"context"

	"github.com/common-fate/httpsig/sigparams"
)

// Verifier verifies message signatures on an incoming HTTP request.
type Verifier struct {
	// NonceStorage is the storage layer
	// to check whether a nonce has been previously seen.
	NonceStorage NonceStorage

	// KeyDirectory is the directory used to look up
	// signing key material based on a key ID.
	KeyDirectory KeyDirectory

	// Tag is an application-specific tag for the signature as a String value.
	// This value is used by applications to help identify signatures relevant for specific applications or protocols.
	// See: https://www.rfc-editor.org/rfc/rfc9421.html#section-2.3-4.12
	//
	// In this verifier implementation a tag MUST be specified.
	// incoming requests must have only one signature matching the tag.
	Tag string

	// Validation is the options to use when validating the
	// signature params.
	Validation sigparams.ValidateOpts

	// Scheme is the expected URL scheme
	// that the verifier is running on.
	//
	// Should be 'https' in production.
	Scheme string

	// Authority is the expected HTTP authority
	// that the verifier is running on.
	Authority string

	// OnDeriveSigningString is a hook which can be used to log
	// the string to sign.
	//
	// This can be useful for debugging signature errors,
	// as you can compare the base signing string between the client
	// and server.
	OnDeriveSigningString func(ctx context.Context, stringToSign string)
}
