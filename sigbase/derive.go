package sigbase

import (
	"fmt"
	"net/http"

	"github.com/common-fate/httpsig/contentdigest"
	"github.com/common-fate/httpsig/sigparams"
)

// Derive a signature base.
//
// When using this in the client context, 'w' may be set to nil.
func Derive(params sigparams.Params, w http.ResponseWriter, req *http.Request, digester contentdigest.Digester) (*Base, error) {
	base := New()

	// For each message component item in the covered components set (in order):
	for _, cc := range params.CoveredComponents {
		// If the component identifier (including its parameters) has already been added to the signature base, produce an error.
		if _, ok := base.Values[cc]; ok {
			return nil, fmt.Errorf("the covered component %q has already been added to the signature base: ensure that it is not repeated multiple times in signer.CoveredComponents", cc)
		}

		val, err := getComponentValue(cc, w, req, digester)
		if err != nil {
			return nil, fmt.Errorf("identifier %q: %w", val, err)
		}

		base.Values[cc] = val

		if cc[0] != '@' && cc != "content-digest" && cc != "content-length" {
			// add the header value to the list of covered headers
			base.Header[cc] = req.Header.Values(cc)
		}
	}

	return base, nil
}
