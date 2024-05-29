package httpsig

import (
	"context"
	"net/http"

	"github.com/common-fate/httpsig/signer"
)

type ClientOpts struct {
	// KeyID is the identifier for the key to use for signing requests.
	KeyID string

	// Tag is an application-specific tag for the signature as a String value.
	// This value is used by applications to help identify signatures relevant for specific applications or protocols.
	// See: https://www.rfc-editor.org/rfc/rfc9421.html#section-2.3-4.12
	Tag string

	// Alg is the signing algorithm to use.
	Alg signer.Algorithm

	// CoveredComponents overrides the default covered components used for signing.
	//
	// If not provided, the following covered components are used:
	// ["@method", "@target-uri", "content-type", "content-length", "content-digest"]
	//
	// CoveredComponents is an ordered set of HTTP message component identifiers for fields (Section 2.1)
	// and derived components (Section 2.2) that indicates the set of message components
	// covered by the signature, never including the @signature-params identifier itself.
	// The order of this set is preserved and communicated between the signer and verifier
	// to facilitate reconstruction of the signature base.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9421.html#section-1.1-7.18.1
	CoveredComponents []string

	// OnDeriveSigningString is a hook which can be used to log
	// the string to sign.
	//
	// This can be useful for debugging signature errors,
	// as you can compare the base signing string between the client
	// and server.
	OnDeriveSigningString func(ctx context.Context, stringToSign string)
}

// NewClient constructs a http.Client which signs
// outgoing HTTP requests with the provided signing algorithm.
//
// For more control, you can use signer.Transport directly.
func NewClient(opts ClientOpts) *http.Client {
	if opts.CoveredComponents == nil {
		opts.CoveredComponents = DefaultCoveredComponents()
	}

	return &http.Client{
		Transport: &signer.Transport{
			KeyID:                 opts.KeyID,
			Tag:                   opts.Tag,
			Alg:                   opts.Alg,
			CoveredComponents:     opts.CoveredComponents,
			OnDeriveSigningString: opts.OnDeriveSigningString,
		},
	}
}

// DefaultCoveredComponents returns a sensible default for the covered components field.
func DefaultCoveredComponents() []string {
	return []string{"@method", "@target-uri", "content-type", "content-length", "content-digest"}
}
