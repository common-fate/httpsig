package sigparams

import "github.com/dunglas/httpsfv"

func (p Params) MarshalText() (text []byte, err error) {
	// Construct the Signature Parameters field (@signature-params)
	// See: https://www.rfc-editor.org/rfc/rfc9421.html#section-2.3
	sigParams := p.SFV()

	got, err := httpsfv.Marshal(sigParams)
	if err != nil {
		return nil, err
	}

	return []byte(got), nil
}
