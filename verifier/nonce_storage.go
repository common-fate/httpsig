package verifier

import "context"

type NonceStorage interface {
	// Seen returns true if a nonce has been previously seen.
	//
	// An error is returned if there was a problem connecting to
	// the storage (for example, if database credentials were invalid).
	//
	// When implementing this interface you MUST mark the input nonce
	// as seen when Seen() is called, to protect against replay attacks.
	Seen(ctx context.Context, nonce string) (bool, error)
}
