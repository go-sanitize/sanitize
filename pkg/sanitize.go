package sanitize

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// TagName is the name of the tag that must be present on the string fields of
// the structs to be sanitized. Defaults to "san".
var TagName = "san"

// SetTagName overrides the default tag name ("san") used by the library.
func SetTagName(n string) {
	TagName = n
}

type fieldSanFn = func(structValue reflect.Value, idx int) error

var fieldSanFns = map[reflect.Kind]fieldSanFn{
	reflect.String:  sanitizeStrField,
	reflect.Int64:   sanitizeInt64Field,
	reflect.Float64: sanitizeFloat64Field,
	reflect.Bool:    sanitizeBoolField,
}

func parseInt64(str string) (int64, error) {
	return strconv.ParseInt(str, 10, 64)
}

func parseFloat64(str string) (float64, error) {
	return strconv.ParseFloat(str, 64)
}

// Struct performs sanitization on all fields of any struct, so long
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
func Struct(s interface{}) error {
	// Get both the value and the type of what the pointer points to. Value is
	// used to mutate underlying data and Type is used to get the name of the
	// field.
	return sanitizeRec(reflect.ValueOf(s).Elem())
}

// Called during recursion, since during recursion we need reflect.Value
// not interface{}.
func sanitizeRec(v reflect.Value) error {
	var structValue reflect.Value
	isPtr := v.Kind() == reflect.Ptr
	if isPtr {
		structValue = v.Elem()
	} else {
		structValue = v
	}

	// Loop through fields of struct. If a struct is encountered, recurse. If a
	// string is encountered, transform it. Else, skip.
	for i := 0; i < structValue.Type().NumField(); i++ {

		var fieldValue reflect.Value
		fieldValue = v.Field(i)
		fmt.Printf("Field value kind: '%+v'\n", fieldValue.Kind())

		if fieldValue.Kind() == reflect.Ptr {
			fieldValue = fieldValue.Elem()
		}

		if fieldValue.Kind() == reflect.Struct {
			err := sanitizeRec(fieldValue)
			if err != nil {
				return err
			}
			continue
		}

		// If not struct, use other sanitization functions
		if sanFn, ok := fieldSanFns[fieldValue.Kind()]; ok {
			if err := sanFn(structValue, i); err != nil {
				return err
			}
			continue
		}

	}

	return nil
}

// sanitizeStrField sanitizes a string field. Requires the whole
// reflect.Value for the struct because it needs access to both the Value and
// Type of the struct.
func sanitizeStrField(structValue reflect.Value, idx int) error {
	var fieldValue = structValue.Field(idx)
	isPtr := fieldValue.Kind() == reflect.Ptr

	tStr, ok := structValue.Type().Field(idx).Tag.Lookup(TagName)

	if !ok {
		// No tag so no sanitization to do
		return nil
	}

	// tag present - process tag string into key-value pairs (ex.
	// min=1 and max=10). Note: some have no value
	comps := strings.Split(tStr, ",")
	kvs := make(map[string]string)
	for _, comp := range comps {
		if strings.Contains(comp, "=") {
			// Use as param. Ex. 'max' with value '42'
			kv := strings.Split(comp, "=")
			kvs[kv[0]] = kv[1]
		} else {
			// Use directly. Ex. 'trim' without value
			kvs[comp] = "_"
		}
	}

	if isPtr && fieldValue.IsNil() {
		// Only handle "def" if it is present, then finish san.
		if _, ok := kvs["def"]; ok {
			defStr := kvs["def"]
			fieldValue.Set(reflect.ValueOf(&defStr))
		}

		return nil
	}

	if isPtr && !fieldValue.IsNil() {
		// Dereference then continue as normal.
		fieldValue = fieldValue.Elem()
	}

	// Trim must happen first, no matter what other components there are.
	if _, ok := kvs["trim"]; ok {
		// Ignore value of this component, we don't care *how* to trim,
		// we just trim.
		oldStr := fieldValue.String()
		fieldValue.SetString(strings.Trim(oldStr, " "))
	}

	// Apply rest of transforms
	if _, ok := kvs["max"]; ok {
		max, err := strconv.ParseInt(kvs["max"], 10, 32)
		if err != nil {
			return err
		}
		oldStr := fieldValue.String()
		if max < int64(len(oldStr)) {
			fieldValue.SetString(oldStr[0:max])
		}
	}

	if _, ok := kvs["lower"]; ok {
		oldStr := fieldValue.String()
		fieldValue.SetString(strings.ToLower(oldStr))
	}

	return nil
}

// sanitizeInt64Field sanitizes an int64 field. Requires the whole
// reflect.Value for the struct because it needs access to both the Value and
// Type of the struct.
func sanitizeInt64Field(structValue reflect.Value, idx int) error {
	var fieldValue = structValue.Field(idx)
	isPtr := fieldValue.Kind() == reflect.Ptr

	tStr, ok := structValue.Type().Field(idx).Tag.Lookup(TagName)

	if !ok {
		// No tag so no sanitization to do
		return nil
	}

	// tag present - process tag string into key-value pairs (ex.
	// min=1 and max=10). Note: some have no value
	comps := strings.Split(tStr, ",")
	kvs := make(map[string]string)
	for _, comp := range comps {
		if strings.Contains(comp, "=") {
			// Use as param. Ex. 'max' with value '42'
			kv := strings.Split(comp, "=")
			kvs[kv[0]] = kv[1]
		} else {
			// Use directly. Ex. 'trim' without value
			kvs[comp] = "_"
		}
	}

	if isPtr && fieldValue.IsNil() {
		// Only handle "def" if it is present, then finish san.
		if _, ok := kvs["def"]; ok {
			defInt64, err := parseInt64(kvs["def"])
			if err != nil {
				return err
			}

			// Look for bad combinations of "def" and error out
			if _, ok := kvs["max"]; ok {
				maxInt64, err := parseInt64(kvs["max"])
				if err != nil {
					return err
				}
				if defInt64 > maxInt64 {
					return fmt.Errorf("incompatible def and max tag components, def (%+v) is higher than max (%+v)", defInt64, maxInt64)
				}
			}
			if _, ok := kvs["min"]; ok {
				minInt64, err := parseInt64(kvs["min"])
				if err != nil {
					return err
				}
				if defInt64 < minInt64 {
					return fmt.Errorf("incompatible def and min tag components, def (%+v) is lower than min (%+v)", defInt64, minInt64)
				}
			}

			fieldValue.Set(reflect.ValueOf(&defInt64))
		}

		return nil
	}

	if isPtr && !fieldValue.IsNil() {
		// Dereference then continue as normal.
		fieldValue = fieldValue.Elem()
	}

	// Check for invalid component combinations
	_, maxOk := kvs["max"]
	_, minOk := kvs["min"]
	if maxOk && minOk {
		if kvs["max"] < kvs["min"] {
			return fmt.Errorf("max less than min on int64 field '%s' during struct sanitization", fieldValue.Type().Name())
		}
	}

	// Loop through pairs and apply string transforms
	for k, v := range kvs {
		if k == "min" {
			min, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return err
			}
			oldNum := fieldValue.Int()
			if min > oldNum {
				fieldValue.SetInt(min)
			}
		}

		if k == "max" {
			max, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return err
			}
			oldNum := fieldValue.Int()
			if max < oldNum {
				fieldValue.SetInt(max)
			}
		}
	}

	return nil
}

// sanitizeInt64Field sanitizes a float64 field. Requires the whole
// reflect.Value for the struct because it needs access to both the Value and
// Type of the struct.
func sanitizeFloat64Field(structValue reflect.Value, idx int) error {
	var fieldValue = structValue.Field(idx)
	isPtr := fieldValue.Kind() == reflect.Ptr

	tStr, ok := structValue.Type().Field(idx).Tag.Lookup(TagName)

	if !ok {
		// No tag so no sanitization to do
		return nil
	}

	// tag present - process tag string into key-value pairs (ex.
	// min=1 and max=10). Note: some have no value
	comps := strings.Split(tStr, ",")
	kvs := make(map[string]string)
	for _, comp := range comps {
		if strings.Contains(comp, "=") {
			// Use as param. Ex. 'max' with value '42'
			kv := strings.Split(comp, "=")
			kvs[kv[0]] = kv[1]
		} else {
			// Use directly. Ex. 'trim' without value
			kvs[comp] = "_"
		}
	}

	if isPtr && fieldValue.IsNil() {
		// Only handle "def" if it is present, then finish san.
		if _, ok := kvs["def"]; ok {
			defFloat64, err := parseFloat64(kvs["def"])
			if err != nil {
				return err
			}

			// Look for bad combinations of "def" and error out
			if _, ok := kvs["max"]; ok {
				maxFloat64, err := parseFloat64(kvs["max"])
				if err != nil {
					return err
				}
				if defFloat64 > maxFloat64 {
					return fmt.Errorf("incompatible def and max tag components, def (%+v) is higher than max (%+v)", defFloat64, maxFloat64)
				}
			}
			if _, ok := kvs["min"]; ok {
				minFloat64, err := parseFloat64(kvs["min"])
				if err != nil {
					return err
				}
				if defFloat64 < minFloat64 {
					return fmt.Errorf("incompatible def and min tag components, def (%+v) is lower than min (%+v)", defFloat64, minFloat64)
				}
			}

			fieldValue.Set(reflect.ValueOf(&defFloat64))
		}

		return nil
	}

	if isPtr && !fieldValue.IsNil() {
		// Dereference then continue as normal.
		fieldValue = fieldValue.Elem()
	}

	// Check for invalid component combinations
	_, maxOk := kvs["max"]
	_, minOk := kvs["min"]
	if maxOk && minOk {
		if kvs["max"] < kvs["min"] {
			return fmt.Errorf("max less than min on float64 field '%s' during struct sanitization", fieldValue.Type().Name())
		}
	}

	// Loop through pairs and apply float64 transforms
	for k, v := range kvs {
		if k == "min" {
			min, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return err
			}
			oldNum := fieldValue.Float()
			if min > oldNum {
				fieldValue.SetFloat(min)
			}
		}

		if k == "max" {
			max, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return err
			}
			oldNum := fieldValue.Float()
			if max < oldNum {
				fieldValue.SetFloat(max)
			}
		}
	}

	return nil
}

// sanitizeBoolField sanitizes a bool field. Requires the whole
// reflect.Value for the struct because it needs access to both the Value and
// Type of the struct.
func sanitizeBoolField(structValue reflect.Value, idx int) error {
	var fieldValue = structValue.Field(idx)
	isPtr := fieldValue.Kind() == reflect.Ptr

	tStr, ok := structValue.Type().Field(idx).Tag.Lookup(TagName)

	if !ok {
		// No tag so no sanitization to do
		return nil
	}

	// tag present - process tag string into key-value pairs (ex.
	// min=1 and max=10). Note: some have no value
	comps := strings.Split(tStr, ",")
	kvs := make(map[string]string)
	for _, comp := range comps {
		if strings.Contains(comp, "=") {
			// Use as param. Ex. 'max' with value '42'
			kv := strings.Split(comp, "=")
			kvs[kv[0]] = kv[1]
		} else {
			// Use directly. Ex. 'trim' without value
			kvs[comp] = "_"
		}
	}

	// Only handle "def". No min or max etc.
	if isPtr && fieldValue.IsNil() {
		if _, ok := kvs["def"]; ok {
			defBool, err := strconv.ParseBool(kvs["def"])
			if err != nil {
				return fmt.Errorf("unable to parse default bool value: %+v", err)
			}

			fieldValue.Set(reflect.ValueOf(&defBool))
		}
	}

	return nil
}
