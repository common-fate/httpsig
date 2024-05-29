// Package signer creates a signature
// over a HTTP request.
package signer

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/common-fate/httpsig/sigset"
)

// getCurrentTime allows the current time to be overridden for testing.
var getCurrentTime = time.Now

// Transport is a HTTP RoundTripper which authenticates
// outgoing requests using HTTP Message Signatures.
//
// The signature schema adheres to RFC9421.
// See: https://www.rfc-editor.org/rfc/rfc9421.html
type Transport struct {
	// KeyID is the identifier for the key to use for signing requests.
	KeyID string

	// Tag is an application-specific tag for the signature as a String value.
	// This value is used by applications to help identify signatures relevant for specific applications or protocols.
	// See: https://www.rfc-editor.org/rfc/rfc9421.html#section-2.3-4.12
	Tag string

	// Alg is the signing algorithm to use.
	Alg Algorithm

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

	// GetNonce can optionally be provided to override the built-in
	// nonce generation function. If the provided Nonce function
	// returns an empty string, a nonce will not be included
	// in the signed request.
	//
	// If Nonce is not provided, a random 32 byte string
	// will be used as the nonce.
	//
	// Including a nonce is recommended. We do not recommend
	// overriding the default behaviour here.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9421.html#section-2.3-4.6
	GetNonce func() (string, error)

	// BaseTransport is the underlying HTTP transport to use
	// for sending requests after they have been signed.
	//
	// If nil, http.DefaultTransport is used.
	BaseTransport http.RoundTripper

	// OnDeriveSigningString is a hook which can be used to log
	// the string to sign.
	//
	// This can be useful for debugging signature errors,
	// as you can compare the base signing string between the client
	// and server.
	OnDeriveSigningString func(ctx context.Context, stringToSign string)
}

// RoundTrip implements the http.RoundTripper interface.
//
// This method will update the 'Signature-Input' and 'Signature' headers with a signature derived from the
// signing algorithm specified with the 'Alg' field.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqBodyClosed := false
	if req.Body != nil {
		defer func() {
			if !reqBodyClosed {
				req.Body.Close()
			}
		}()
	}

	// parse the existing signature set on the request
	set, err := sigset.Unmarshal(req)
	if err != nil {
		return nil, err
	}

	// derive the signature.
	ms, err := t.Sign(req)
	if err != nil {
		return nil, err
	}

	// as per the http.RoundTripper contract, roundtrippers
	// may not modify the request.
	req2 := cloneRequest(req)

	// add the signature to the set
	set.Add(ms)

	// include the signature in the cloned HTTP request.
	err = set.Include(req2)
	if err != nil {
		return nil, fmt.Errorf("including signature in HTTP request: %w", err)
	}

	// req.Body is assumed to be closed by the base RoundTripper.
	reqBodyClosed = true

	return t.base().RoundTrip(req2)
}

func (t *Transport) base() http.RoundTripper {
	if t.BaseTransport != nil {
		return t.BaseTransport
	}
	return http.DefaultTransport
}

// cloneRequest returns a clone of the provided *http.Request.
// The clone is a shallow copy of the struct and its Header map.
func cloneRequest(r *http.Request) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header, len(r.Header))
	for k, s := range r.Header {
		r2.Header[k] = append([]string(nil), s...)
	}
	return r2
}
