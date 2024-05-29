package signer

// Labeler generate a label to be used for a HTTP signature.
//
// An HTTP message signature is identified by a label within an HTTP message.
// This label MUST be unique within a given HTTP message and MUST be used in
// both the Signature-Input field and the Signature field. The label is chosen
// by the signer, except where a specific label is dictated by protocol
// negotiations such as those described in Section 5.
type Labeler interface {
	Label(existingCount int) string
}
