package sanitize

import (
	"reflect"
	"strings"
)

func (s Sanitizer) fieldTags(f reflect.StructTag) map[string]string {
	m := make(map[string]string)

	tStr, ok := f.Lookup(s.tagName)
	if !ok {
		// No tag so no sanitization to do
		return m
	}

	// tag present - process tag string into key-value pairs (ex.
	// min=1 and max=10). Note: some have no value
	comps := strings.Split(tStr, ",")
	for _, comp := range comps {
		if strings.Contains(comp, "=") {
			// Use as param. Ex. 'max' with value '42'
			kv := strings.Split(comp, "=")
			m[kv[0]] = kv[1]
		} else {
			// Use directly. Ex. 'trim' without value
			m[comp] = "_"
		}
	}

	return m
}
