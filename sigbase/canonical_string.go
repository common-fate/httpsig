package sigbase

import (
	"fmt"

	"github.com/common-fate/httpsig/ascii"
	"github.com/common-fate/httpsig/sigparams"
)

// CanonicalString returns the canonical signing string based on the signature
// parameters.
//
// params.CoveredComponents is used to determine the order which covered components
// are printed to the canonical string.
func (b Base) CanonicalString(params sigparams.Params) (string, error) {
	// Let the output be an empty string.
	var output ascii.Writer

	alreadyCovered := map[string]bool{}

	// For each message component item in the covered components set (in order):
	for _, cc := range params.CoveredComponents {
		// If the component identifier (including its parameters) has already been added to the signature base, produce an error.
		if alreadyCovered[cc] {
			return "", fmt.Errorf("the covered component %q has already been added to the signature base: ensure that it is not repeated multiple times in signer.CoveredComponents", cc)
		}

		alreadyCovered[cc] = true

		// Append the component identifier for the covered component serialized according to the component-identifier ABNF rule. Note that this serialization places the component name
		// in double quotes and appends any parameters outside of the quotes.
		// NOTE(chrnorm): we currently support a subset of this and only support component names, not parameters.
		_, err := output.WriteString(`"`)
		if err != nil {
			return "", err
		}
		_, err = output.WriteString(cc)
		if err != nil {
			return "", err
		}
		// Append a single colon (:).
		// Append a single space (" ").
		_, err = output.WriteString(`": `)
		if err != nil {
			return "", err
		}

		val, ok := b.Values[cc]
		if !ok {
			return "", fmt.Errorf("covered component %q did not have a corresponding value", cc)
		}

		// Append the covered component's canonicalized component value.
		_, err = output.WriteString(val)
		if err != nil {
			return "", err
		}

		// Append a single newline (\n).
		_, err = output.WriteString("\n")
		if err != nil {
			return "", err
		}
	}

	// Append the signature parameters component (Section 2.3) according to the signature-params-line rule
	// See: https://www.rfc-editor.org/rfc/rfc9421.html#signature-params

	_, err := output.WriteString(`"@signature-params": `)
	if err != nil {
		return "", err
	}

	sigParamsStr, err := params.MarshalText()
	if err != nil {
		return "", fmt.Errorf("marshalling signature params: %w", err)
	}

	_, err = output.Write(sigParamsStr)
	if err != nil {
		return "", fmt.Errorf("writing signature params value: %w", err)
	}

	return output.String(), nil
}
