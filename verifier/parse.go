package verifier

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/common-fate/httpsig/sigbase"
	"github.com/common-fate/httpsig/sigset"
)

// Verification of an HTTP message signature is
// a process that takes as its input the signature context
// (including the target message, particularly its Signature
// and Signature-Input fields) and the requirements for the application.
//
// The output of the verification is either a positive verification or an error.
//
// See: https://www.rfc-editor.org/rfc/rfc9421.html#section-3.2
//
// This method returns a parsed http.Request with all non-covered headers removed.
// The request body is also removed unless 'content-digest' and 'content-length'
// are included in the covered components.
func (v *Verifier) Parse(w http.ResponseWriter, req *http.Request, now time.Time) (*http.Request, Algorithm, error) {
	ctx := req.Context()

	if req.Host != v.Authority {
		return nil, nil, fmt.Errorf("request host %q was not equal to expected authority %q", req.Host, v.Authority)
	}

	// set the scheme and authority based on our expected settings,
	// so that they are used when deriving the canonical string to sign.
	req.URL.Scheme = v.Scheme
	req.URL.Host = v.Authority

	// Parse the Signature and Signature-Input fields as described in Sections 4.1 and 4.2,
	// and extract the signatures to be verified and their labels.

	// If there is more than one signature value present,
	// determine which signature should be processed for
	// this message based on the policy and configuration of the verifier.
	// If an applicable signature is not found, produce an error.

	// Our implementation looks up the signature input matching the 'Tag'
	// field on the verifier.
	// We must find only a single signature input matching the tag,
	// otherwise the request is invalid.

	set, err := sigset.Unmarshal(req)
	if err != nil {
		return nil, nil, err
	}

	msg, err := set.Find(v.Tag)
	if err != nil {
		return nil, nil, fmt.Errorf("finding matching signature: %w", err)
	}

	// Validate the signature params.
	err = msg.Input.Validate(v.Validation, now)
	if err != nil {
		return nil, nil, err
	}

	// Validate the nonce has not been seen before.
	seen, err := v.NonceStorage.Seen(ctx, msg.Input.Nonce)
	if err != nil {
		return nil, nil, err
	}
	if seen {
		return nil, nil, errors.New("nonce has already been seen")
	}

	// Find the key associated with the Key ID.
	//
	//  Start with the set of allowable algorithms known to the application. If any of the
	// following steps select an algorithm that is not in this set, the signature validation fails.
	//
	// 6.2. If the algorithm is known through external means such as static configuration or
	// external protocol negotiation, the verifier will use that algorithm.
	//
	// 6.3. If the algorithm can be determined from the keying material, such as through an
	// algorithm field on the key value itself, the verifier will use that algorithm.
	//
	// 6.4. If the algorithm is explicitly stated in the signature parameters using a value
	// from the "HTTP Signature Algorithms" registry, the verifier will use the referenced algorithm.
	key, err := v.KeyDirectory.GetKey(ctx, msg.Input.KeyID, msg.Input.Alg)
	if err != nil {
		return nil, nil, err
	}

	// 6.5. If the algorithm is specified in more than one location (e.g., a combination of static
	// configuration, the algorithm signature parameter, and the key material itself), the resolved
	// algorithms MUST be the same. If the algorithms are not the same, the verifier MUST fail the verification.
	if msg.Input.Alg != "" && msg.Input.Alg != key.Type() {
		return nil, nil, fmt.Errorf("invalid algorithm signature parameter: wanted %q but got %q", key.Type(), msg.Input.Alg)
	}

	// Use the received HTTP message and the parsed signature parameters to recreate the
	// signature base, using the algorithm defined in Section 2.5. The value of the
	// @signature-params input is the value of the Signature-Input field
	// for this signature serialized according to the rules described in Section 2.3.
	//
	// Note that this does not include the signature's label from the Signature-Input field.
	base, err := sigbase.Derive(msg.Input, w, req, key.ContentDigest())
	if err != nil {
		return nil, nil, fmt.Errorf("recreating signature base: %w", err)
	}

	stringToSign, err := base.CanonicalString(msg.Input)
	if err != nil {
		return nil, nil, fmt.Errorf("recreating string to sign: %w", err)
	}

	if v.OnDeriveSigningString != nil {
		v.OnDeriveSigningString(req.Context(), stringToSign)
	}

	// Verify the signature using the provided algorithm.
	err = key.Verify(ctx, stringToSign, msg.Signature)
	if err != nil {
		return nil, nil, fmt.Errorf("verifying signature: %w", err)
	}

	r2 := new(http.Request)
	*r2 = *req

	// copy the covered HTTP headers to the cloned request
	r2.Header = base.Header

	if !base.BodyIsCovered() {
		if req.Body != nil {
			err = req.Body.Close()
			if err != nil {
				return nil, nil, fmt.Errorf("error closing original request body because it is not covered by the HTTP signature: %w", err)
			}
		}
		// strip the request body as it isn't signed, so we
		// can't trust it.
		r2.Body = io.NopCloser(UncoveredBody{})
	}

	return r2, key, nil
}
