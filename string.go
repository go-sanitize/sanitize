package sanitize

import (
	"reflect"
	"strconv"
	"strings"
)

// sanitizeStrField sanitizes a string field. Requires the whole
// reflect.Value for the struct because it needs access to both the Value and
// Type of the struct.
func sanitizeStrField(s Sanitizer, structValue reflect.Value, idx int) error {
	fieldValue := structValue.Field(idx)
	isPtr := fieldValue.Kind() == reflect.Ptr

	tags := s.fieldTags(structValue.Type().Field(idx).Tag)

	if isPtr && fieldValue.IsNil() {
		// Only handle "def" if it is present, then finish san.
		if _, ok := tags["def"]; ok {
			defStr := tags["def"]
			fieldValue.Set(reflect.ValueOf(&defStr))
		}

		return nil
	}

	if isPtr && !fieldValue.IsNil() {
		// Dereference then continue as normal.
		fieldValue = fieldValue.Elem()
	}

	// Trim must happen first, no matter what other components there are.
	if _, ok := tags["trim"]; ok {
		// Ignore value of this component, we don't care *how* to trim,
		// we just trim.
		oldStr := fieldValue.String()
		fieldValue.SetString(strings.Trim(oldStr, " "))
	}

	// Apply rest of transforms
	if _, ok := tags["max"]; ok {
		max, err := strconv.ParseInt(tags["max"], 10, 32)
		if err != nil {
			return err
		}
		oldStr := fieldValue.String()
		if max < int64(len(oldStr)) {
			fieldValue.SetString(oldStr[0:max])
		}
	}

	if _, ok := tags["lower"]; ok {
		oldStr := fieldValue.String()
		fieldValue.SetString(strings.ToLower(oldStr))
	}

	return nil
}
