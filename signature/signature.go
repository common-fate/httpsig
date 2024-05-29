package signature

import (
	"github.com/common-fate/httpsig/sigparams"
)

// Message is a HTTP Message Signature as per RFC9421.
type Message struct {
	// Input is applied as the Signature-Input header
	Input sigparams.Params

	// Signature is applied as the Siganture header.
	Signature []byte
}
