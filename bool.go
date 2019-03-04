package sanitize

import (
	"fmt"
	"reflect"
	"strconv"
)

// sanitizeBoolField sanitizes a bool field. Requires the whole
// reflect.Value for the struct because it needs access to both the Value and
// Type of the struct.
func sanitizeBoolField(s Sanitizer, structValue reflect.Value, idx int) error {
	fieldValue := structValue.Field(idx)

	tags := s.fieldTags(structValue.Type().Field(idx).Tag)

	if fieldValue.Kind() == reflect.Ptr && !fieldValue.IsNil() {
		fieldValue = fieldValue.Elem()
	}

	isSlice := fieldValue.Kind() == reflect.Slice

	var fields []reflect.Value
	if !isSlice {
		fields = []reflect.Value{fieldValue}
	} else {
		for i := 0; i < fieldValue.Len(); i++ {
			fields = append(fields, fieldValue.Index(i))
		}
	}

	for _, field := range fields {
		isPtr := field.Kind() == reflect.Ptr

		// Only handle "def". No min or max etc.
		if isPtr && field.IsNil() {
			if _, ok := tags["def"]; ok {
				defBool, err := strconv.ParseBool(tags["def"])
				if err != nil {
					return fmt.Errorf("unable to parse default bool value: %+v", err)
				}

				field.Set(reflect.ValueOf(&defBool))
			}
		}
	}

	return nil
}
