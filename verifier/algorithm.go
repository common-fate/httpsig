package verifier

import (
	"context"

	"github.com/common-fate/httpsig/contentdigest"
)

// Algorithm to verify the incoming signed HTTP request with.
// The Type must be a valid entry in the HTTP Signature Algorithms registry
// https://www.rfc-editor.org/rfc/rfc9421.html#name-initial-contents
type Algorithm interface {
	Type() string
	Verify(ctx context.Context, base string, signature []byte) error
	ContentDigest() contentdigest.Digester
}
