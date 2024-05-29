package signer

import (
	"context"

	"github.com/common-fate/httpsig/contentdigest"
)

type Algorithm interface {
	Type() string
	Sign(ctx context.Context, base string) ([]byte, error)
	// ContentDigest specifies the HTTP body digest algorithm
	// to use when covering the 'content-digest' component
	// on an HTTP request.
	ContentDigest() contentdigest.Digester
}
