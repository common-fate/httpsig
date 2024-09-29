package alg_hmac

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"

	"github.com/common-fate/httpsig"
	"github.com/common-fate/httpsig/contentdigest"
	"github.com/common-fate/httpsig/signer"
	"github.com/common-fate/httpsig/verifier"
)

const HMAC_SHA256 = "hmac-sha256" // Algo is the HMAC algorithm name

// HMAC is a signer and verifier for HMAC digests. It uses crypto/hmac with sha256,
// and implements the httpsig.Attributer interface
type HMAC struct {
	Key   []byte
	Attrs any
}

// NewHMAC creates a new HMAC with the provided key
func NewHMAC(key []byte) *HMAC {
	return NewHMACWithAttributes(key, nil)
}

// NewHMACWithAttributes creates a new HMAC with the provided key and attributes
func NewHMACWithAttributes(key []byte, attrs any) *HMAC {
	return &HMAC{Key: key, Attrs: attrs}
}

var _ signer.Algorithm = &HMAC{}
var _ verifier.Algorithm = &HMAC{}
var _ httpsig.Attributer = &HMAC{}

func (h *HMAC) Type() string {
	return HMAC_SHA256
}

func (h *HMAC) Attributes() any {
	return h.Attrs
}

func (h *HMAC) Sign(ctx context.Context, base string) ([]byte, error) {
	if len(h.Key) == 0 {
		return nil, errors.New("no key provided")
	}
	return hmac.New(sha256.New, h.Key).Sum([]byte(base)), nil
}

func (h *HMAC) Verify(ctx context.Context, base string, sig []byte) error {
	selfSig, err := h.Sign(ctx, base)
	if err != nil {
		return err
	}
	// constant time compare
	if !hmac.Equal(selfSig, sig) {
		return errors.New("signature mismatch")
	}
	return nil
}

func (h *HMAC) ContentDigest() contentdigest.Digester {
	return contentdigest.SHA256
}
