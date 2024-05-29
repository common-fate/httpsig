package sigbase

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"unicode"

	"github.com/common-fate/httpsig/contentdigest"
	"github.com/dunglas/httpsfv"
)

type Hasher interface {
	io.Writer
	Sum() []byte
}

// getComponentValue determines the component value for the component identifier, following
// the process described in https://www.rfc-editor.org/rfc/rfc9421.html#section-2.5-7.2.2.5.1
//
// If the component identifier has a parameter that is not understood, produce an error.
//
// If the component identifier has parameters that are mutually incompatible with one another,
// such as bs and sf, produce an error.
//
// If the component identifier contains the req parameter and the target message is a request,
// produce an error.
//
// If the component identifier contains the req parameter and the target message is a response,
// the context for the component value is the related request message of the target response message.
// Otherwise, the context for the component value is the target message.
//
// If the component name starts with an "at" (@) character, derive the component's value from the
// message according to the specific rules defined for the derived component, as provided in Section 2.2,
// including processing of any known valid parameters. If the derived component name is unknown
// or the value cannot be derived, produce an error.
//
// If the component name does not start with an "at" (@) character, canonicalize the HTTP field
// value as described in Section 2.1, including processing of any known valid parameters.
// If the field cannot be found in the message or the value cannot be obtained in the context,
// produce an error.
func getComponentValue(identifier string, w http.ResponseWriter, r *http.Request, digester contentdigest.Digester) (string, error) {
	if identifier == "" {
		return "", errors.New("identifier was empty")
	}

	if !isLower(identifier) {
		return "", errors.New("identifier must be lowercase")
	}

	switch identifier {
	case "@signature-params":
		return "", errors.New("@signature-params may not be included in the covered components")

	case "@method":
		val := r.Method
		if val == "" {
			return "", errors.New("request method was empty")
		}
		return val, nil

	case "@authority":
		val := r.Host
		if val == "" {
			return "", errors.New("request host was empty")
		}
		return val, nil

	case "@scheme":
		val := r.URL.Scheme
		if val == "" {
			return "", errors.New("request scheme was empty")
		}
		return val, nil

	case "@target-uri":
		u := r.URL

		// prevent mismatch between clients and servers:
		// the Go client does not include a trailing slash
		// if the path is empty.
		if u.Path == "" {
			u.Path = "/"
		}
		val := r.URL.String()
		if val == "" {
			return "", errors.New("request URL was empty")
		}
		return val, nil

	case "content-length":
		return httpsfv.Marshal(httpsfv.NewItem(r.ContentLength))

	case "content-digest":
		return digester.HashRequest(w, r)
	}

	if identifier[0] == '@' {
		// the derived component name is unknown
		return "", errors.New("unknown component name")
	}

	// If the component name does not start with an "at" (@) character, canonicalize the HTTP field
	// value as described in Section 2.1, including processing of any known valid parameters.
	// If the field cannot be found in the message or the value cannot be obtained in the context,
	// produce an error.

	// Create an ordered list of the field values of each instance of the field in the
	// message, in the order they occur (or will occur) in the message.
	values := r.Header.Values(identifier)

	if len(values) == 0 {
		return "", errors.New("HTTP header was empty")
	}

	parsedValues := make([]string, len(values))

	for i, val := range values {
		var headerValue []string

		lines := strings.Split(val, "\n")

		// Strip leading and trailing whitespace from each item in the list. Note that since HTTP
		// field values are not allowed to contain leading and trailing whitespace, this would be
		// a no-op in a compliant implementation.
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if len(line) > 0 {
				headerValue = append(headerValue, line)
			}
		}

		// Remove any obsolete line folding within the line, and replace it with a single space (" "),
		// as discussed in Section 5.2 of [HTTP/1.1]. Note that this behavior is specific to HTTP/1.1
		// and does not apply to other versions of the HTTP specification, which do not allow internal
		// line folding
		parsedValues[i] = strings.Join(headerValue, " ")
	}

	// Concatenate the list of values with a single comma (",")
	// and a single space (" ") between each item.
	itemStr := strings.Join(parsedValues, ", ")

	return itemStr, nil
}

func isLower(s string) bool {
	for _, r := range s {
		if !unicode.IsLower(r) && unicode.IsLetter(r) {
			return false
		}
	}
	return true
}
