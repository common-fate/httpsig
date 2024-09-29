package signer

import (
	"context"

	"github.com/common-fate/httpsig/contentdigest"
)

// Algorithm is an interface for signing HTTP requests.
// The Type must be a valid entry in the HTTP Signature Algorithms registry
// https://www.rfc-editor.org/rfc/rfc9421.html#name-initial-contents
type Algorithm interface {
	Type() string
	Sign(ctx context.Context, base string) ([]byte, error)
	// ContentDigest specifies the HTTP body digest algorithm
	// to use when covering the 'content-digest' component
	// on an HTTP request.
	ContentDigest() contentdigest.Digester
}
