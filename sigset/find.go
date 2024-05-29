package sigset

import (
	"errors"
	"fmt"

	"github.com/common-fate/httpsig/signature"
)

type MultipleSignaturesError struct {
	Tag    string
	First  string
	Second string
}

func (e MultipleSignaturesError) Error() string {
	return fmt.Sprintf("found multiple signatures for tag %q: %q and %q", e.Tag, e.First, e.Second)
}

// Find a signature matching the tag.
//
// If the signature cannot be found, or there are multiple
// signatures matching the tag, an error is returned.
//
// Returns an error if the supplied tag is empty.
func (s *Set) Find(tag string) (*signature.Message, error) {
	if tag == "" {
		return nil, errors.New("tag to find was empty")
	}

	var found string

	for k, v := range s.Messages {
		if v.Input.Tag != tag {
			continue
		}

		if found != "" {
			// we've found multiple signatures matching the tag
			err := MultipleSignaturesError{
				Tag:    tag,
				First:  found,
				Second: k,
			}
			return nil, err
		}

		found = k
	}

	if found == "" {
		return nil, fmt.Errorf("could not find a signature matching the tag %q", tag)
	}

	return s.Messages[found], nil
}
