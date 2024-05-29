// Package signature set provides a data structure
// describing a set of HTTP message signatures.
package sigset

import "github.com/common-fate/httpsig/signature"

// Set of signatures in an HTTP request.
//
// The index of the map is the label given to the signatures.
// When parsing signatures do not rely upon the label,
// use the tag in the signature params instead.
type Set struct {
	Messages map[string]*signature.Message
}
