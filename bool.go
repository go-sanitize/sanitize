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
	isPtr := fieldValue.Kind() == reflect.Ptr

	tags := s.fieldTags(structValue.Type().Field(idx).Tag)

	// Only handle "def". No min or max etc.
	if isPtr && fieldValue.IsNil() {
		if _, ok := tags["def"]; ok {
			defBool, err := strconv.ParseBool(tags["def"])
			if err != nil {
				return fmt.Errorf("unable to parse default bool value: %+v", err)
			}

			fieldValue.Set(reflect.ValueOf(&defBool))
		}
	}

	return nil
}
