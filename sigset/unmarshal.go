package sigset

import (
	"fmt"
	"net/http"

	"github.com/common-fate/httpsig/signature"
	"github.com/common-fate/httpsig/sigparams"
	"github.com/dunglas/httpsfv"
)

// Unmarshal a set of signatures from an HTTP request,
// by reading the Signature-Input and Signature headers.
//
// The Signature-Input field identifies the covered components and parameters
// that describe how the signature was generated, while the Signature field
// contains the signature value. Each field MAY contain multiple labeled values.
//
// An HTTP message signature is identified by a label within an HTTP message.
// This label MUST be unique within a given HTTP message and MUST be used in
// both the Signature-Input field and the Signature field. The label is chosen
// by the signer, except where a specific label is dictated by protocol
// negotiations such as those described in Section 5.
//
// An HTTP message signature MUST use both the Signature-Input field and
// the Signature field, and each field MUST contain the same labels.
// The presence of a label in one field but not the other is an error.
func Unmarshal(r *http.Request) (*Set, error) {
	sigInputDict, err := httpsfv.UnmarshalDictionary(r.Header.Values("Signature-Input"))
	if err != nil {
		// refuse to sign a request if the existing Signature-Input is malformed.
		return nil, fmt.Errorf("Signature-Input header is malformed: %w", err)
	}

	sigDict, err := httpsfv.UnmarshalDictionary(r.Header.Values("Signature"))
	if err != nil {
		// refuse to sign a request if the existing Signature is malformed.
		return nil, fmt.Errorf("Signature header but it is malformed: %w", err)
	}

	// track signatures that we've seen, so that we can ensure there aren't any Signature fields
	// that don't have a corresponding Signature-Input.
	parsedInputs := map[string]bool{}

	s := Set{
		Messages: map[string]*signature.Message{},
	}

	for _, field := range sigInputDict.Names() {
		val, _ := sigInputDict.Get(field)

		list, ok := val.(httpsfv.InnerList)
		if !ok {
			return nil, fmt.Errorf("could not cast signature input field %s to a httpsfv.InnerList, got type %T", field, val)
		}

		// parse the params
		p, err := sigparams.UnmarshalInnerList(list)
		if err != nil {
			return nil, fmt.Errorf("unmarshalling signature params: %w", err)
		}

		// find the matching signature
		sig, found := sigDict.Get(field)
		if !found {
			return nil, fmt.Errorf("signature input %q had no corresponding signature", field)
		}

		sigItem, ok := sig.(httpsfv.Item)
		if !ok {
			return nil, fmt.Errorf("could not cast signature %q to a httpsfv.Item", field)
		}

		sigBytes, ok := sigItem.Value.([]byte)
		if !ok {
			return nil, fmt.Errorf("could not cast signature %q to bytes", field)
		}

		s.Messages[field] = &signature.Message{
			Input:     *p,
			Signature: sigBytes,
		}

		parsedInputs[field] = true
	}

	// check that there aren't any signatures that don't have a corresponding Signature-Input.
	for _, k := range sigDict.Names() {
		if !parsedInputs[k] {
			return nil, fmt.Errorf("signature %q did not have a corresponding Signature-Input field", k)
		}
	}

	return &s, nil
}
