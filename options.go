package sanitize

// Option represents an optional setting for the sanitizer library
type Option interface {
	id() string
	value() string
}

// OptionTagName allows users to use custom tag names for the structs
type OptionTagName struct {
	Value string
}

var _ Option = OptionTagName{}

const optionTagNameID = "tag-name"

func (o OptionTagName) id() string {
	return optionTagNameID
}

func (o OptionTagName) value() string {
	return o.Value
}
