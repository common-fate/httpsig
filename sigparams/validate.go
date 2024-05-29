package sigparams

import (
	"errors"
	"fmt"
	"time"
)

type ValidateOpts struct {
	// ForbidClientSideAlg requires that the client-side alg specifier
	// is empty.
	ForbidClientSideAlg bool

	// BeforeDuration is the duration before now which a signature is invalid.
	// This should be set to a small value in production, such as time.Minute.
	BeforeDuration time.Duration

	// AfterDuration is the duration after now which a signature is invalid.
	// This should be set to zero in production to prevent
	// signatures being validated with a timestamp that is in the future.
	AfterDuration time.Duration

	// RequiredCoveredComponents, if specified, requires a set of mandatory
	// covered components which must be included in the params.
	RequiredCoveredComponents map[string]bool

	// RequireNonce, if true, requires the 'nonce' field to be set.
	RequireNonce bool
}

func (p Params) Validate(opts ValidateOpts, now time.Time) error {
	if opts.ForbidClientSideAlg && p.Alg != "" {
		return fmt.Errorf("client side alg specification is forbidden but alg %q was provided", p.Alg)
	}

	if !p.Expires.IsZero() && p.Expires.Before(p.Created) {
		return fmt.Errorf("expires timestamp %s was before created timestamp %s", p.Expires, p.Created)
	}

	notBefore := now.Add(-opts.BeforeDuration)

	if p.Created.Before(notBefore) {
		return fmt.Errorf("created timestamp %s was earlier than earliest allowed value %s", p.Created, notBefore)
	}

	notAfter := now.Add(opts.AfterDuration)

	if p.Created.After(notAfter) {
		return fmt.Errorf("created timestamp %s was after latest allowed value %s", p.Created, notAfter)
	}

	if !p.Expires.IsZero() && p.Expires.Before(notAfter) {
		return fmt.Errorf("expires timestamp %s was before latest allowed value %s", p.Expires, notAfter)
	}

	if opts.RequireNonce && p.Nonce == "" {
		return errors.New("nonce is required")
	}

	allComponents := map[string]bool{}

	for _, cc := range p.CoveredComponents {
		allComponents[cc] = true
	}

	for required := range opts.RequiredCoveredComponents {
		if !allComponents[required] {
			return fmt.Errorf("required covered component %q was not present", required)
		}
	}

	return nil
}
