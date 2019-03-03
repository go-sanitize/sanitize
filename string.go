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
	if _, ok := tags["upper"]; ok {
		oldStr := fieldValue.String()
		fieldValue.SetString(strings.ToUpper(oldStr))
	}
	if _, ok := tags["title"]; ok {
		oldStr := fieldValue.String()
		fieldValue.SetString(toTitle(oldStr))
	}
	if _, ok := tags["cap"]; ok {
		oldStr := fieldValue.String()
		fieldValue.SetString(toCap(oldStr))
	}

	return nil
}

func toTitle(s string) string {
	b := make([]byte, len(s))
	casediff := byte('a' - 'A')
	inWord := false
	for i := 0; i < len(s); i++ {
		b[i] = s[i]
		c := b[i]
		isLower := c >= 'a' && c <= 'z'
		isUpper := c >= 'A' && c <= 'Z'
		if !inWord && isLower { // Not inside a word and it's lower case
			b[i] -= casediff
		}
		if inWord && isUpper { // Inside a word and it's upper case
			b[i] += casediff
		}
		inWord = isLower || isUpper
	}
	return string(b)
}

func toCap(s string) string {
	b := make([]byte, len(s))
	casediff := byte('a' - 'A')
	i := 0
	for ; i < len(s); i++ { // Looking for first character
		b[i] = s[i]
		c := b[i]
		if c >= 'A' && c <= 'Z' { // Already capitalized
			i++
			break
		}
		if c >= 'a' && c <= 'z' { // Must be capitalized
			b[i] -= casediff
			i++
			break
		}
	}
	for ; i < len(s); i++ { // Lowering all other characters
		b[i] = s[i]
		c := b[i]
		if c >= 'A' && c <= 'Z' {
			b[i] += casediff
		}
	}
	return string(b)
}
