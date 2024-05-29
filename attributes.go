package httpsig

import (
	"context"
)

type contextKey struct {
	name string
}

var attributesContext = contextKey{name: "attributesContext"}

// AttributesFromContext returns server-side attributes associated
// with the verified signing key.
//
// To obtain the attributes you must run httpsig.Middleware.
func AttributesFromContext(ctx context.Context) any {
	return ctx.Value(attributesContext)
}
