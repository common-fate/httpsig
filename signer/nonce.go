package signer

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func (t *Transport) nonce() (string, error) {
	if t.GetNonce != nil {
		return t.GetNonce()
	}

	return randomNonce()
}

// randomNonce generates a random 32 byte nonce.
func randomNonce() (string, error) {
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return "", fmt.Errorf("could not generate nonce: %w", err)
	}

	return base64.URLEncoding.EncodeToString(nonceBytes), nil
}
