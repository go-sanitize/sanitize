package sanitize

import (
	"fmt"
	"reflect"
	"strconv"
)

// sanitizeInt64Field sanitizes a float64 field. Requires the whole
// reflect.Value for the struct because it needs access to both the Value and
// Type of the struct.
func sanitizeFloat64Field(s Sanitizer, structValue reflect.Value, idx int) error {
	fieldValue := structValue.Field(idx)
	isPtr := fieldValue.Kind() == reflect.Ptr

	tags := s.fieldTags(structValue.Type().Field(idx).Tag)

	if isPtr && fieldValue.IsNil() {
		// Only handle "def" if it is present, then finish san.
		if _, ok := tags["def"]; ok {
			defFloat64, err := parseFloat64(tags["def"])
			if err != nil {
				return err
			}

			// Look for bad combinations of "def" and error out
			if _, ok := tags["max"]; ok {
				maxFloat64, err := parseFloat64(tags["max"])
				if err != nil {
					return err
				}
				if defFloat64 > maxFloat64 {
					return fmt.Errorf(
						"incompatible def and max tag components, def (%+v) is "+
							"higher than max (%+v)",
						defFloat64,
						maxFloat64,
					)
				}
			}
			if _, ok := tags["min"]; ok {
				minFloat64, err := parseFloat64(tags["min"])
				if err != nil {
					return err
				}
				if defFloat64 < minFloat64 {
					return fmt.Errorf(
						"incompatible def and min tag components, def (%+v) is "+
							"lower than min (%+v)",
						defFloat64,
						minFloat64,
					)
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
	_, maxOk := tags["max"]
	_, minOk := tags["min"]
	if maxOk && minOk {
		if tags["max"] < tags["min"] {
			return fmt.Errorf(
				"max less than min on float64 field '%s' during struct sanitization",
				fieldValue.Type().Name(),
			)
		}
	}

	// Loop through pairs and apply float64 transforms
	for k, v := range tags {
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
