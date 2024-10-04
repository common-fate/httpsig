package alg_hmac

import (
	"context"
	"errors"

	"github.com/common-fate/httpsig/verifier"
)

type singleHMACKeyDirectory struct {
	hmac *HMAC
}

// NewSingleHMACKeyDirectory creates a new in-memory SingleHMACKeyDirectory with the provided key.
// All parameters are ignored in the GetKey() method, and it will never error.
func NewSingleHMACKeyDirectory(hmac *HMAC) verifier.KeyDirectory {
	return singleHMACKeyDirectory{hmac: hmac}
}

var _ verifier.KeyDirectory = &singleHMACKeyDirectory{}

func (d singleHMACKeyDirectory) GetKey(ctx context.Context, kid string, _ string) (verifier.Algorithm, error) {
	return d.hmac, nil
}

type multiHMACKeyDirectory struct {
	keys map[string]HMAC
}

// NewMultiHMACKeyDirectory creates a new in-memory MultiHMACKeyDirectory with
// the provided map of keyID to HMAC
//
// GetKey() will validate the algorithm and return the HMAC if it is found
func NewMultiHMACKeyDirectory(keys map[string]HMAC) verifier.KeyDirectory {
	return &multiHMACKeyDirectory{keys: keys}
}

var _ verifier.KeyDirectory = &multiHMACKeyDirectory{}

func (d multiHMACKeyDirectory) GetKey(ctx context.Context, kid string, alg string) (verifier.Algorithm, error) {
	if alg != HMAC_SHA256 {
		return nil, errors.New("unsupported algorithm for directory")
	}

	hmac, ok := d.keys[kid]
	if !ok {
		return nil, errors.New("key not found")
	}
	return &hmac, nil
}
