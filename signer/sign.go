package signer

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/common-fate/httpsig/sigbase"
	"github.com/common-fate/httpsig/signature"
	"github.com/common-fate/httpsig/sigparams"
)

// Sign a HTTP request following the process described in https://www.rfc-editor.org/rfc/rfc9421.html#section-3.1.
//
// This method will update the 'Signature-Input' and 'Signature' headers with a signature derived from the
// signing algorithm specified with the 'Alg' field.
func (t *Transport) Sign(req *http.Request) (*signature.Message, error) {
	if t.Alg == nil {
		return nil, errors.New("algorithm must not be nil")
	}

	nonce, err := t.nonce()
	if err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	params := sigparams.Params{
		KeyID:             t.KeyID,
		Tag:               t.Tag,
		Alg:               t.Alg.Type(),
		Created:           getCurrentTime(),
		CoveredComponents: t.CoveredComponents,
		Nonce:             nonce,
	}

	// derive the signature base following the process in https://www.rfc-editor.org/rfc/rfc9421.html#create-sig-input
	base, err := sigbase.Derive(params, nil, req, t.Alg.ContentDigest())
	if err != nil {
		return nil, fmt.Errorf("deriving signature base: %w", err)
	}

	stringToSign, err := base.CanonicalString(params)
	if err != nil {
		return nil, fmt.Errorf("creating string to sign: %w", err)
	}

	if t.OnDeriveSigningString != nil {
		t.OnDeriveSigningString(req.Context(), stringToSign)
	}

	// sign the signature base according to the signing algorithm
	sig, err := t.Alg.Sign(req.Context(), stringToSign)
	if err != nil {
		return nil, fmt.Errorf("error signing request: %w", err)
	}

	// construct the HTTP message signature
	output := signature.Message{
		Input:     params,
		Signature: sig,
	}

	return &output, nil
}
