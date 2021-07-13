package sanitize

import (
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// sanitizeStrField sanitizes a string field. Requires the whole
// reflect.Value for the struct because it needs access to both the Value and
// Type of the struct.
func sanitizeStrField(s Sanitizer, structValue reflect.Value, idx int) error {
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
		if isPtr && field.IsNil() {
			// Only handle "def" if it is present, then finish san.
			if _, ok := tags["def"]; ok {
				defStr := tags["def"]
				field.Set(reflect.ValueOf(&defStr))
			}

			return nil
		}

		if isPtr && !field.IsNil() {
			// Dereference then continue as normal.
			field = field.Elem()
		}

		// Let's strip out invalid characters before anything else
		if _, ok := tags["xss"]; ok {
			oldStr := field.String()
			field.SetString(xss(oldStr))
		}

		// Trim must happen before the other tags, no matter what other
		// components there are.
		if _, ok := tags["trim"]; ok {
			// Ignore value of this component, we don't care *how* to trim,
			// we just trim.
			oldStr := field.String()
			field.SetString(strings.Trim(oldStr, " "))
		}

		// Apply rest of transforms
		if _, ok := tags["date"]; ok {
			oldStr := field.String()
			field.SetString(date(s.dateInput, s.dateKeepFormat, s.dateOutput, oldStr))
		}
		if _, ok := tags["max"]; ok {
			max, err := strconv.ParseInt(tags["max"], 10, 32)
			if err != nil {
				return err
			}
			oldStr := field.String()
			if max < int64(len(oldStr)) {
				field.SetString(oldStr[0:max])
			}
		}
		if _, ok := tags["lower"]; ok {
			oldStr := field.String()
			field.SetString(strings.ToLower(oldStr))
		}
		if _, ok := tags["upper"]; ok {
			oldStr := field.String()
			field.SetString(strings.ToUpper(oldStr))
		}
		if _, ok := tags["title"]; ok {
			oldStr := field.String()
			field.SetString(toTitle(oldStr))
		}
		if _, ok := tags["cap"]; ok {
			oldStr := field.String()
			field.SetString(toCap(oldStr))
		}
	}

	return nil
}

func toTitle(s string) string {
	return strings.Title(strings.ToLower((s)))
}

func toCap(s string) string {
	b := make([]byte, len(s))
	casediff := byte('a' - 'A')
	i := 0
	for ; i < len(s); i++ { // Looking for first character
		b[i] = s[i]
		c := b[i]
		if c >= 'A' && c <= 'Z' { // Already capitalized
			break
		}
		if c >= 'a' && c <= 'z' { // Must be capitalized
			b[i] -= casediff
			break
		}
	}
	i++
	for ; i < len(s); i++ { // Lowering all other characters
		b[i] = s[i]
		c := b[i]
		if c >= 'A' && c <= 'Z' {
			b[i] += casediff
		}
	}
	return string(b)
}

var replaceWhitespaces = regexp.MustCompile(`\s\s+`)
var blacklistStripping = regexp.MustCompile(`[\p{Me}\p{C}<>=;(){}\[\]?]`)

func xss(s string) string {
	s = blacklistStripping.ReplaceAllString(s, " ")
	s = replaceWhitespaces.ReplaceAllString(s, " ")
	return s
}

func date(in []string, keepFormat bool, out, v string) string {
	for _, f := range in {
		t, err := time.Parse(f, v)
		if err != nil {
			continue
		}
		outf := f
		if !keepFormat {
			outf = out
		}
		return t.Format(outf)
	}
	return ""
}
