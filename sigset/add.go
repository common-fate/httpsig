package sigset

import (
	"strconv"

	"github.com/common-fate/httpsig/signature"
)

// Add a signature message to the set.
//
// Add() gives a label such as 'sig1'
// 'sig2', 'sig3' etc to the message.
//
// To customise the label, add the message
// to the Messages field directly.
func (s *Set) Add(m *signature.Message) {
	label := "sig" + strconv.Itoa(len(s.Messages)+1)
	s.Messages[label] = m
}
