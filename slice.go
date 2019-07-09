package sanitize

import (
	"reflect"
	"strconv"
)

// sanitizeSliceField sanitizes a slice field. Requires the whole
// reflect.Value for the slice because it needs access to both the Value and
// Type of the slice.
func sanitizeSliceField(s Sanitizer, structValue reflect.Value, idx int) error {
	fieldValue := structValue.Field(idx)

	tags := s.fieldTags(structValue.Type().Field(idx).Tag)

	if fieldValue.Kind() == reflect.Ptr && !fieldValue.IsNil() {
		fieldValue = fieldValue.Elem()
	}

	if _, ok := tags["maxsize"]; ok {
		max, err := strconv.ParseInt(tags["maxsize"], 10, 32)
		if err != nil {
			return err
		}
		if fieldValue.Len() < int(max) {
			return nil
		}
		fieldValue.Set(fieldValue.Slice(0, int(max)))
	}

	return nil
}
