package sigbase

import "net/http"

// The signature base is used to derive the canonicalized
// HTTP message components covered by the signature.
//
// See: https://www.rfc-editor.org/rfc/rfc9421.html#name-creating-the-signature-base
type Base struct {
	Values map[string]string

	// Header is an HTTP header with
	// key/value pairs that have been added to the base.
	//
	// Header is intended for use in HTTP request middleware
	// rather than for signature verification.
	//
	// The header values are copied as-is from the input request
	// and whitespace trimming / obsolete line folding is not
	// performed on these.
	Header http.Header
}

func New() *Base {
	return &Base{
		Values: map[string]string{},
		Header: http.Header{},
	}
}
