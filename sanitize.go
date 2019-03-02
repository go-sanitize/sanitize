package sanitize

import (
	"fmt"
	"reflect"
	//"strings"
)

// DefaultTagName intance is the name of the tag that must be present on the string
// fields of the structs to be sanitized. Defaults to "san".
const DefaultTagName = "san"

// Sanitizer intance
type Sanitizer struct {
	tagName string
}

// New sanitizer instance
func New(options ...Option) (*Sanitizer, error) {
	s := &Sanitizer{
		tagName: DefaultTagName,
	}
	for _, o := range options {
		switch o.id() {
		case optionTagNameID:
			v := o.value()
			if len(v) < 1 || len(v) > 10 {
				return nil, fmt.Errorf("tag name %q must be between 1 and 10 characters", v)
			}
			s.tagName = v
		default:
			return nil, fmt.Errorf("tag name %q is not valid", o.value())
		}
	}
	return s, nil
}

// Sanitize performs sanitization on all fields of any struct, so long
// as the sanitization tag ("san" by default) has been defined on the string
// fields of the struct. The argument s must be the address of a struct to
// mutate.
//
// Will recursively check all struct, *struct, string, *string, int64, *int64,
// float64, *float64, bool, and *bool fields. Pointers are dereferenced and the
// data pointed to will be sanitized.
//
// Errors are returned as the struct's fields are processed, so the struct may
// not be in the same state as when the function began if an error is
// returned.
func (s *Sanitizer) Sanitize(o interface{}) error {
	// Get both the value and the type of what the pointer points to. Value is
	// used to mutate underlying data and Type is used to get the name of the
	// field.
	return s.sanitizeRec(reflect.ValueOf(o).Elem())
}

type fieldSanFn = func(s Sanitizer, structValue reflect.Value, idx int) error

var fieldSanFns = map[string]fieldSanFn{
	"string":   sanitizeStrField,
	"*string":  sanitizeStrField,
	"int64":    sanitizeInt64Field,
	"*int64":   sanitizeInt64Field,
	"float64":  sanitizeFloat64Field,
	"*float64": sanitizeFloat64Field,
	"bool":     sanitizeBoolField,
	"*bool":    sanitizeBoolField,
}

// Called during recursion, since during recursion we need reflect.Value
// not interface{}.
func (s Sanitizer) sanitizeRec(v reflect.Value) error {
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	// Loop through fields of struct. If a struct is encountered, recurse. If a
	// string is encountered, transform it. Else, skip.
	for i := 0; i < v.Type().NumField(); i++ {
		field := v.Field(i)
		fkind := field.Kind()

		// If the field is a struct, sanitize it recursively
		if fkind == reflect.Struct {
			if err := s.sanitizeRec(field); err != nil {
				return err
			}
			continue
		}

		// If not struct, use other sanitization functions
		ftype := field.Type()
		if sanFn, ok := fieldSanFns[ftype.String()]; ok {
			if err := sanFn(s, v, i); err != nil {
				return err
			}
		}
	}

	return nil
}
