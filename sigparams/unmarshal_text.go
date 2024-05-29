package sigparams

import (
	"errors"
	"fmt"
	"time"

	"github.com/dunglas/httpsfv"
)

func UnmarshalInnerList(input httpsfv.InnerList) (*Params, error) {
	var p Params
	var err error

	if len(input.Items) > 0 {
		p.CoveredComponents = make([]string, len(input.Items))

		for i, item := range input.Items {
			str, ok := item.Value.(string)
			if !ok {
				return nil, errors.New("could not cast covered component item to string")
			}
			p.CoveredComponents[i] = str
		}
	}

	p.Alg, err = getOptionalString(input.Params, "alg")
	if err != nil {
		return nil, err
	}

	p.KeyID, err = getOptionalString(input.Params, "keyid")
	if err != nil {
		return nil, err
	}

	p.Tag, err = getOptionalString(input.Params, "tag")
	if err != nil {
		return nil, err
	}

	p.Nonce, err = getOptionalString(input.Params, "nonce")
	if err != nil {
		return nil, err
	}

	p.Created, err = getOptionalUnixTimestamp(input.Params, "created")
	if err != nil {
		return nil, err
	}

	p.Expires, err = getOptionalUnixTimestamp(input.Params, "expires")
	if err != nil {
		return nil, err
	}

	return &p, nil
}

// getOptionalString extracts a string value from a httpsfv.Params struct.
func getOptionalString(v *httpsfv.Params, key string) (string, error) {
	val, ok := v.Get(key)
	if !ok {
		return "", nil
	}
	str, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("looking up %q: value was not a string", key)
	}
	return str, nil
}

// getOptionalUnixTimestamp extracts a unix timestamp value from a httpsfv.Params struct.
func getOptionalUnixTimestamp(v *httpsfv.Params, key string) (time.Time, error) {
	val, ok := v.Get(key)
	if !ok {
		return time.Time{}, nil
	}

	ts, ok := val.(int64)
	if !ok {
		return time.Time{}, fmt.Errorf("looking up %q: value was not an int64, got %T", key, val)
	}

	return time.Unix(int64(ts), 0), nil
}
