// Package sanitize provides an easy way to clean fields in structs: trimming, applying maximum
// string lengths, minimum numeric values, default values, and so on
package sanitize

import (
	"fmt"
	"reflect"
)

// DefaultTagName intance is the name of the tag that must be present on the string
// fields of the structs to be sanitized. Defaults to "san".
const DefaultTagName = "san"

// Sanitizer intance
type Sanitizer struct {
	tagName        string
	dateInput      []string
	dateKeepFormat bool
	dateOutput     string
}

// New sanitizer instance
func New(options ...Option) (*Sanitizer, error) {
	s := &Sanitizer{
		tagName: DefaultTagName,
	}
	for _, o := range options {
		switch o.id() {
		case optionTagNameID:
			v := o.value().(string)
			if len(v) < 1 || len(v) > 10 {
				return nil, fmt.Errorf("tag name %q must be between 1 and 10 characters", v)
			}
			s.tagName = v
		case optionDateFormatID:
			v := o.value().(OptionDateFormat)
			s.dateInput = v.Input
			s.dateKeepFormat = v.KeepFormat
			s.dateOutput = v.Output
		default:
			return nil, fmt.Errorf("option %q is not valid", o.id())
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
	"string":      sanitizeStrField,
	"[]string":    sanitizeStrField,
	"*[]string":   sanitizeStrField,
	"*string":     sanitizeStrField,
	"[]*string":   sanitizeStrField,
	"*[]*string":  sanitizeStrField,
	"int":         sanitizeIntField,
	"[]int":       sanitizeIntField,
	"*[]int":      sanitizeIntField,
	"*int":        sanitizeIntField,
	"[]*int":      sanitizeIntField,
	"*[]*int":     sanitizeIntField,
	"int8":        sanitizeInt8Field,
	"[]int8":      sanitizeInt8Field,
	"*[]int8":     sanitizeInt8Field,
	"*int8":       sanitizeInt8Field,
	"[]*int8":     sanitizeInt8Field,
	"*[]*int8":    sanitizeInt8Field,
	"int16":       sanitizeInt16Field,
	"[]int16":     sanitizeInt16Field,
	"*[]int16":    sanitizeInt16Field,
	"*int16":      sanitizeInt16Field,
	"[]*int16":    sanitizeInt16Field,
	"*[]*int16":   sanitizeInt16Field,
	"int32":       sanitizeInt32Field,
	"[]int32":     sanitizeInt32Field,
	"*[]int32":    sanitizeInt32Field,
	"*int32":      sanitizeInt32Field,
	"[]*int32":    sanitizeInt32Field,
	"*[]*int32":   sanitizeInt32Field,
	"int64":       sanitizeInt64Field,
	"[]int64":     sanitizeInt64Field,
	"*[]int64":    sanitizeInt64Field,
	"*int64":      sanitizeInt64Field,
	"[]*int64":    sanitizeInt64Field,
	"*[]*int64":   sanitizeInt64Field,
	"uint":        sanitizeUintField,
	"[]uint":      sanitizeUintField,
	"*[]uint":     sanitizeUintField,
	"*uint":       sanitizeUintField,
	"[]*uint":     sanitizeUintField,
	"*[]*uint":    sanitizeUintField,
	"uint8":       sanitizeUint8Field,
	"[]uint8":     sanitizeUint8Field,
	"*[]uint8":    sanitizeUint8Field,
	"*uint8":      sanitizeUint8Field,
	"[]*uint8":    sanitizeUint8Field,
	"*[]*uint8":   sanitizeUint8Field,
	"uint16":      sanitizeUint16Field,
	"[]uint16":    sanitizeUint16Field,
	"*[]uint16":   sanitizeUint16Field,
	"*uint16":     sanitizeUint16Field,
	"[]*uint16":   sanitizeUint16Field,
	"*[]*uint16":  sanitizeUint16Field,
	"uint32":      sanitizeUint32Field,
	"[]uint32":    sanitizeUint32Field,
	"*[]uint32":   sanitizeUint32Field,
	"*uint32":     sanitizeUint32Field,
	"[]*uint32":   sanitizeUint32Field,
	"*[]*uint32":  sanitizeUint32Field,
	"uint64":      sanitizeUint64Field,
	"[]uint64":    sanitizeUint64Field,
	"*[]uint64":   sanitizeUint64Field,
	"*uint64":     sanitizeUint64Field,
	"[]*uint64":   sanitizeUint64Field,
	"*[]*uint64":  sanitizeUint64Field,
	"float32":     sanitizeFloat32Field,
	"[]float32":   sanitizeFloat32Field,
	"*[]float32":  sanitizeFloat32Field,
	"*float32":    sanitizeFloat32Field,
	"[]*float32":  sanitizeFloat32Field,
	"*[]*float32": sanitizeFloat32Field,
	"float64":     sanitizeFloat64Field,
	"[]float64":   sanitizeFloat64Field,
	"*[]float64":  sanitizeFloat64Field,
	"*float64":    sanitizeFloat64Field,
	"[]*float64":  sanitizeFloat64Field,
	"*[]*float64": sanitizeFloat64Field,
	"bool":        sanitizeBoolField,
	"[]bool":      sanitizeBoolField,
	"*[]bool":     sanitizeBoolField,
	"*bool":       sanitizeBoolField,
	"[]*bool":     sanitizeBoolField,
	"*[]*bool":    sanitizeBoolField,
}

// Called during recursion, since during recursion we need reflect.Value
// not interface{}.
func (s Sanitizer) sanitizeRec(v reflect.Value) error {
	// Loop through fields of struct. If a struct is encountered, recurse. If a
	// string is encountered, transform it. Else, skip.
	for i := 0; i < v.Type().NumField(); i++ {
		field := v.Field(i)
		fkind := field.Kind()

		// If the field is a slice, sanitize it first
		isPtrToSlice := fkind == reflect.Ptr && field.Elem().Kind() == reflect.Slice
		isSlice := fkind == reflect.Slice
		if isSlice || isPtrToSlice {
			if err := sanitizeSliceField(s, v, i); err != nil {
				return err
			}
		}

		// Do we have a special sanitization function for this type? If so, use it
		ftype := field.Type().String()
		if sanFn, ok := fieldSanFns[ftype]; ok {
			if err := sanFn(s, v, i); err != nil {
				return err
			}
		}

		// If the field is a struct, sanitize it recursively
		isPtrToStruct := fkind == reflect.Ptr && field.Elem().Kind() == reflect.Struct
		if fkind == reflect.Struct || isPtrToStruct {
			if isPtrToStruct {
				field = field.Elem()
			}
			if err := s.sanitizeRec(field); err != nil {
				return err
			}
			continue
		}

		// If the field is a slice of structs, recurse through them
		if isSlice || isPtrToSlice {
			if isPtrToSlice {
				field = field.Elem()
			}
			for i := 0; i < field.Len(); i++ {
				f := field.Index(i)
				if f.Kind() == reflect.Ptr {
					f = f.Elem()
				}
				if f.Kind() != reflect.Struct {
					continue
				}
				if err := s.sanitizeRec(f); err != nil {
					return err
				}
			}
			continue
		}
	}

	return nil
}
