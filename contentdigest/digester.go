package contentdigest

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"

	"github.com/dunglas/httpsfv"
)

// Digester creates a HTTP request digest in the format specified by
// https://www.rfc-editor.org/rfc/rfc9530.html#content-digest.
type Digester struct {
	// Key to give the digest.
	Key string
	// HashFunc is a function which returns the hashing algorithm to use.
	HashFunc func() hash.Hash

	// MaxBytes is the limit of bytes to read to prevent DOS attacks.
	MaxBytes int64
}

// SHA256 is a digester which uses the SHA256 hashing algorithm and key,
// with MaxBytes set to 10MB.
var SHA256 = Digester{
	Key:      "sha-256",
	HashFunc: sha256.New,
	MaxBytes: 10485760, // 10 MB
}

// SHA512 is a digester which uses the SHA512 hashing algorithm and key,
// with MaxBytes set to 10MB.
var SHA512 = Digester{
	Key:      "sha-512",
	HashFunc: sha512.New,
	MaxBytes: 10485760, // 10 MB
}

// HashRequest hashes a HTTP request and returns a string following the specification in
// https://www.rfc-editor.org/rfc/rfc9530.html#content-digest
//
// Hashing is performed by reading the HTTP request into memory. To prevent DOS,
// a http.MaxBytesReader is used to limit the body size that can be read.
//
// 'w' is used to signal to the Go HTTP library that a connection should be closed
// if the client is exceeding the maximum bytes.
// When using this client-side, 'w' may be set to nil.
func (d Digester) HashRequest(w http.ResponseWriter, r *http.Request) (string, error) {
	if d.HashFunc == nil {
		return "", errors.New("digester: getHash must be defined")
	}
	if d.Key == "" {
		return "", errors.New("digester: key must not be empty")
	}

	h := d.HashFunc()

	var buf bytes.Buffer

	if r.Body != nil && r.Body != http.NoBody {
		defer r.Body.Close()
		maxBytesReader := http.MaxBytesReader(w, r.Body, d.MaxBytes)

		reader := io.TeeReader(maxBytesReader, h)

		_, err := io.Copy(&buf, reader)
		if err != nil {
			return "", fmt.Errorf("error copying HTTP request body to hash: %w", err)
		}

		// replace the request body, as we have now read it all into memory.
		r.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
	}

	digest := h.Sum(nil)

	dict := httpsfv.NewDictionary()
	dict.Add(d.Key, httpsfv.NewItem(digest))

	return httpsfv.Marshal(dict)
}
