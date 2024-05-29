package verifier

import "context"

type KeyDirectory interface {
	// GetKey looks up a signing key based on the key ID.
	//
	// It is not recommended to use the clientSpecifiedAlg, although this
	// is provided to adhere to the RFC spec.
	GetKey(ctx context.Context, kid string, clientSpecifiedAlg string) (Algorithm, error)
}
