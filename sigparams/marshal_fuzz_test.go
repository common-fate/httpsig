package sigparams

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dunglas/httpsfv"
	"github.com/google/go-cmp/cmp"
)

func FuzzMarshal(f *testing.F) {
	testcases := [][]string{
		{"testkey", "foo", "alg", "example,second", "nonce", "0", "0"},
		{"", "", "", "", "aweihuarhew", "1716978392", "0"},
	}
	for _, tc := range testcases {
		f.Add(tc[0], tc[1], tc[2], tc[3], tc[4], tc[5], tc[6])
	}
	f.Fuzz(func(t *testing.T, keyID, tag, alg, coveredComponents, nonce, created, expires string) {

		p := Params{
			KeyID:             keyID,
			Tag:               tag,
			Alg:               alg,
			CoveredComponents: strings.Split(coveredComponents, ","),
		}

		createdTs, err := strconv.ParseInt(created, 10, 0)
		if err == nil {
			p.Created = time.Unix(createdTs, 0)
		}

		expiresTs, err := strconv.ParseInt(expires, 10, 0)
		if err == nil {
			p.Expires = time.Unix(expiresTs, 0)
		}

		txt, err1 := p.MarshalText()
		if err1 != nil {
			return
		}

		l, err := httpsfv.UnmarshalList([]string{string(txt)})
		if err != nil {
			return
		}

		il := l[0].(httpsfv.InnerList)

		read, err2 := UnmarshalInnerList(il)
		if err2 != nil {
			t.Errorf("unmarshalling params: %s", err2)
		}

		if diff := cmp.Diff(&p, read); diff != "" {
			t.Errorf("UnmarshalInnerList() mismatch (-want +got):\n%s", diff)
		}
	})
}
