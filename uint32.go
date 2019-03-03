package sanitize

import (
	"fmt"
	"reflect"
)

// sanitizeUint32Field sanitizes an Uint32 field. Requires the whole
// reflect.Value for the struct because it needs access to both the Value and
// Type of the struct.
func sanitizeUint32Field(s Sanitizer, structValue reflect.Value, idx int) error {
	fieldValue := structValue.Field(idx)
	isPtr := fieldValue.Kind() == reflect.Ptr

	tags := s.fieldTags(structValue.Type().Field(idx).Tag)

	var err error

	// Minimum value
	_, hasMin := tags["min"]
	min := uint32(0)
	if hasMin {
		min, err = parseUint32(tags["min"])
		if err != nil {
			return err
		}
	}

	// Maximum value
	_, hasMax := tags["max"]
	max := uint32(0)
	if hasMax {
		max, err = parseUint32(tags["max"])
		if err != nil {
			return err
		}
	}

	// Checking if minimum is not higher than maximum
	if hasMax && hasMin && max < min {
		return fmt.Errorf(
			"max less than min on Uint32 field '%s' during struct sanitization",
			fieldValue.Type().Name(),
		)
	}
	// Checking if minimum and maximum are above 0
	if (hasMin && min < 0) || (hasMax && max < 0) {
		return fmt.Errorf(
			"min and max on Uint32 field '%s' can not be below 0",
			fieldValue.Type().Name(),
		)
	}

	// Default value
	_, hasDef := tags["def"]
	def := uint32(0)
	if hasDef {
		def, err = parseUint32(tags["def"])
		if err != nil {
			return err
		}

		// Making sure default is not smaller than min or higher than max
		if hasMax && def > max {
			return fmt.Errorf(
				"incompatible def and max tag components, def (%+v) is "+
					"higher than max (%+v)",
				def,
				max,
			)
		}
		if hasMin && def < min {
			return fmt.Errorf(
				"incompatible def and min tag components, def (%+v) is "+
					"lower than min (%+v)",
				def,
				min,
			)
		}
	}

	// PoUinter, nil, and we have a default: set it
	if isPtr && fieldValue.IsNil() && hasDef {
		fieldValue.Set(reflect.ValueOf(&def))
		return nil
	}

	// Not nil poUinter. Dereference then continue as normal
	if isPtr && !fieldValue.IsNil() {
		fieldValue = fieldValue.Elem()
	}

	// Apply min and max transforms
	if hasMin {
		oldNum := uint32(fieldValue.Uint())
		if min > oldNum {
			fieldValue.SetUint(uint64(min))
		}
	}
	if hasMax {
		oldNum := uint32(fieldValue.Uint())
		if max < oldNum {
			fieldValue.SetUint(uint64(max))
		}
	}

	return nil
}
