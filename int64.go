package sanitize

import (
	"fmt"
	"reflect"
	"strconv"
)

// sanitizeInt64Field sanitizes an int64 field. Requires the whole
// reflect.Value for the struct because it needs access to both the Value and
// Type of the struct.
func sanitizeInt64Field(s Sanitizer, structValue reflect.Value, idx int) error {
	fieldValue := structValue.Field(idx)
	isPtr := fieldValue.Kind() == reflect.Ptr

	tags := s.fieldTags(structValue.Type().Field(idx).Tag)

	if isPtr && fieldValue.IsNil() {
		// Only handle "def" if it is present, then finish san.
		if _, ok := tags["def"]; ok {
			defInt64, err := parseInt64(tags["def"])
			if err != nil {
				return err
			}

			// Look for bad combinations of "def" and error out
			if _, ok := tags["max"]; ok {
				maxInt64, err := parseInt64(tags["max"])
				if err != nil {
					return err
				}
				if defInt64 > maxInt64 {
					return fmt.Errorf(
						"incompatible def and max tag components, def (%+v) is "+
							"higher than max (%+v)",
						defInt64,
						maxInt64,
					)
				}
			}
			if _, ok := tags["min"]; ok {
				minInt64, err := parseInt64(tags["min"])
				if err != nil {
					return err
				}
				if defInt64 < minInt64 {
					return fmt.Errorf(
						"incompatible def and min tag components, def (%+v) is "+
							"lower than min (%+v)",
						defInt64,
						minInt64,
					)
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
	_, maxOk := tags["max"]
	_, minOk := tags["min"]
	if maxOk && minOk {
		if tags["max"] < tags["min"] {
			return fmt.Errorf(
				"max less than min on int64 field '%s' during struct sanitization",
				fieldValue.Type().Name(),
			)
		}
	}

	// Loop through pairs and apply string transforms
	for k, v := range tags {
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
