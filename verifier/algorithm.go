package verifier

import (
	"context"

	"github.com/common-fate/httpsig/contentdigest"
)

// Algorithm to verify the incoming signed HTTP request with.
type Algorithm interface {
	Type() string
	Verify(ctx context.Context, base string, signature []byte) error
	ContentDigest() contentdigest.Digester
}
