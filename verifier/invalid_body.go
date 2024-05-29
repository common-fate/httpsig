package verifier

import "errors"

var ErrBodyNotCovered = errors.New("the body cannot be read because it is not covered by a HTTP signature: include 'content-digest' and 'content-length' in the signature to fix this")

// UncoveredBody is an io.Reader which returns
// ErrBodyNotCovered when being read.
//
// It is used to guard against applications
// treating an unsigned HTTP request body as trusted.
type UncoveredBody struct {
}

func (b UncoveredBody) Read(p []byte) (n int, err error) {
	return 0, ErrBodyNotCovered
}
