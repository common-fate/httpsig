package signer

import (
	"context"

	"github.com/common-fate/httpsig/contentdigest"
)

// testAlgorithm is a signature algorithm used
// in unit tests inside this package.
type testAlgorithm struct {
	AlgType   string
	Signature string
	SignErr   error
}

func (t testAlgorithm) ContentDigest() contentdigest.Digester {
	return contentdigest.SHA256
}

func (t testAlgorithm) Type() string {
	return t.AlgType
}

func (t testAlgorithm) Sign(ctx context.Context, base string) ([]byte, error) {
	return []byte(t.Signature), t.SignErr
}
