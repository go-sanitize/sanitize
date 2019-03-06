package sanitize

// Option represents an optional setting for the sanitizer library
type Option interface {
	id() string
	value() interface{}
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

func (o OptionTagName) value() interface{} {
	return o.Value
}

// OptionDateFormat allows users to specify what date formats are accepted
// as input and what is expected as output. You can choose to force the date
// to be parsed in a different format, or keep the original format
type OptionDateFormat struct {
	Input      []string
	KeepFormat bool
	Output     string
}

var _ Option = OptionDateFormat{}

const optionDateFormatID = "date-format"

func (o OptionDateFormat) id() string {
	return optionDateFormatID
}

func (o OptionDateFormat) value() interface{} {
	return o
}
