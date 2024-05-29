package sigparams

import (
	"time"
)

// Params are the HTTP message signing parameters.
//
// They are included in a canonical base request under the '@signature-params' field.
//
// See: https://www.rfc-editor.org/rfc/rfc9421.html#name-signature-parameters
type Params struct {
	// KeyID is the identifier for the key to use for signing requests.
	KeyID string

	// Tag is an application-specific tag for the signature as a String value.
	// This value is used by applications to help identify signatures relevant for specific applications or protocols.
	// See: https://www.rfc-editor.org/rfc/rfc9421.html#section-2.3-4.12
	Tag string

	Alg string

	// CoveredComponents specify the components of the request
	// to be covered with the signature.
	//
	// An ordered set of HTTP message component identifiers for fields (Section 2.1)
	// and derived components (Section 2.2) that indicates the set of message components
	// covered by the signature, never including the @signature-params identifier itself.
	// The order of this set is preserved and communicated between the signer and verifier
	// to facilitate reconstruction of the signature base.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9421.html#section-1.1-7.18.1
	CoveredComponents []string

	Nonce string

	Created time.Time

	Expires time.Time
}
