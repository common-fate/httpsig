package sigparams

import "github.com/dunglas/httpsfv"

// SFV converts the params to a HTTP structured field value.
func (p Params) SFV() *httpsfv.InnerList {
	// Construct the Signature Parameters field (@signature-params)
	// See: https://www.rfc-editor.org/rfc/rfc9421.html#section-2.3
	sigParams := httpsfv.InnerList{
		Items:  make([]httpsfv.Item, len(p.CoveredComponents)),
		Params: httpsfv.NewParams(),
	}

	for i, cc := range p.CoveredComponents {
		sigParams.Items[i] = httpsfv.NewItem(cc)
	}

	if p.KeyID != "" {
		sigParams.Params.Add("keyid", p.KeyID)
	}

	if p.Alg != "" {
		sigParams.Params.Add("alg", p.Alg)
	}

	if p.Tag != "" {
		sigParams.Params.Add("tag", p.Tag)
	}

	if p.Nonce != "" {
		sigParams.Params.Add("nonce", p.Nonce)
	}

	if !p.Created.IsZero() {
		sigParams.Params.Add("created", p.Created.Unix())
	}
	if !p.Expires.IsZero() {
		sigParams.Params.Add("expires", p.Expires.Unix())
	}

	return &sigParams
}
