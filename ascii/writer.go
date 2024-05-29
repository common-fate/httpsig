package ascii

import (
	"fmt"
	"strings"
	"unicode"
)

// Writer is a wrapper over strings.Builder
// which only writes ASCII characters.
//
// Attempting to write a non-ASCII character will
// return an error.
type Writer struct {
	output strings.Builder
}

func (w *Writer) WriteString(s string) (int, error) {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return 0, fmt.Errorf("cannot write a non-ASCII character (character code %v)", s[i])
		}

		// strings.Builder *always* returns a nil error.
		_ = w.output.WriteByte(s[i])
	}
	return len(s), nil
}

func (w *Writer) Write(s []byte) (int, error) {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return 0, fmt.Errorf("cannot write a non-ASCII character (character code %v)", s[i])
		}

		// strings.Builder *always* returns a nil error.
		_ = w.output.WriteByte(s[i])
	}
	return len(s), nil
}

func (w *Writer) String() string {
	return w.output.String()
}
