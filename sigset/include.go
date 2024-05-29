package sigset

import (
	"fmt"
	"net/http"

	"github.com/dunglas/httpsfv"
)

// Include a signature set in an HTTP request by
// setting the Signature-Input and Signature headers.
//
// If Signature-Input or Signature headers exist they
// will be overwritten.
func (s *Set) Include(r *http.Request) error {
	sigInputDict := httpsfv.NewDictionary()
	sigDict := httpsfv.NewDictionary()

	for k, v := range s.Messages {
		sigInputDict.Add(k, v.Input.SFV())
		sigDict.Add(k, httpsfv.NewItem(v.Signature))
	}

	sigInputString, err := httpsfv.Marshal(sigInputDict)
	if err != nil {
		return fmt.Errorf("marshalling Signature-Input header: %w", err)
	}

	r.Header.Set("Signature-Input", sigInputString)

	sigString, err := httpsfv.Marshal(sigDict)
	if err != nil {
		return fmt.Errorf("marshalling Signature header: %w", err)
	}

	r.Header.Set("Signature", sigString)

	return nil
}
