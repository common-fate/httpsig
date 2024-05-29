package sigbase

// BodyIsCovered is true if the base has 'content-length'
// and 'content-digest'.
func (b Base) BodyIsCovered() bool {
	return b.Values["content-length"] != "" && b.Values["content-digest"] != ""
}
