package sanitize

import (
	"reflect"
	"testing"
	"unsafe"
)

type unknownOption struct{}

var _ Option = unknownOption{}

func (o unknownOption) id() string {
	return "strangetag!"
}

func (o unknownOption) value() interface{} {
	return "very strange indeed"
}

// sanitizersEqual checks for equality between two sanitizers in a manner similar to reflect.DeepEqual.
//
// We have to check equality manually due to sanitizer functions.
//
//	From reflect docs: "Func values are deeply equal if both are nil; otherwise they are not deeply equal."
func sanitizersEqual(s *Sanitizer, o *Sanitizer) bool {
	if s == nil && o == nil {
		return true
	} else if (s != nil && o == nil) || (s == nil && o != nil) {
		return false
	}

	if !reflect.DeepEqual(s.tagName, o.tagName) {
		return false
	}

	if !reflect.DeepEqual(s.dateInput, o.dateInput) {
		return false
	}

	if !reflect.DeepEqual(s.dateKeepFormat, o.dateKeepFormat) {
		return false
	}

	if !reflect.DeepEqual(s.dateOutput, o.dateOutput) {
		return false
	}

	if s.sanitizersByName == nil && o.sanitizersByName == nil {
		return true
	} else if (s.sanitizersByName != nil && o.sanitizersByName == nil) || (s.sanitizersByName == nil && o.sanitizersByName != nil) {
		return false
	}

	var sKeys []string
	for k, _ := range s.sanitizersByName {
		sKeys = append(sKeys, k)
	}

	var oKeys []string
	for k, _ := range o.sanitizersByName {
		oKeys = append(oKeys, k)
	}

	if !reflect.DeepEqual(sKeys, oKeys) {
		return false
	}

	for _, k := range sKeys {
		psf := s.sanitizersByName[k]
		osf := o.sanitizersByName[k]
		upsf := *(*unsafe.Pointer)(unsafe.Pointer(&psf))
		upof := *(*unsafe.Pointer)(unsafe.Pointer(&osf))

		if !reflect.DeepEqual(upsf, upof) {
			return false
		}
	}

	return true
}

func doNothing(s Sanitizer, structValue reflect.Value, idx int) error {
	return nil
}

func Test_New(t *testing.T) {
	type args struct {
		options []Option
	}
	tests := []struct {
		name    string
		args    args
		want    *Sanitizer
		wantErr bool
	}{
		{
			name: "no options",
			args: args{
				options: []Option{},
			},
			want: &Sanitizer{
				tagName: DefaultTagName,
			},
			wantErr: false,
		},
		{
			name: "unknown option",
			args: args{
				options: []Option{
					unknownOption{},
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "valid tag name option",
			args: args{
				options: []Option{
					OptionTagName{Value: "mytag"},
				},
			},
			want: &Sanitizer{
				tagName: "mytag",
			},
			wantErr: false,
		},
		{
			name: "invalid tag name option (too short)",
			args: args{
				options: []Option{
					OptionTagName{Value: ""},
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "invalid tag name option (too big)",
			args: args{
				options: []Option{
					OptionTagName{Value: "thistagiswaytoolarge"},
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "unknown tag",
			args: args{
				options: []Option{
					OptionTagName{Value: "thistagiswaytoolarge"},
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "valid sanitizer func option",
			args: args{
				options: []Option{
					OptionSanitizerFunc{Name: "capfirst", Sanitizer: capFirst},
				},
			},
			want: &Sanitizer{
				tagName: DefaultTagName,
				sanitizersByName: map[string]SanitizerFunc{
					"capfirst": capFirst,
				},
			},
			wantErr: false,
		},
		{
			name: "duplicate sanitizer func option",
			args: args{
				options: []Option{
					OptionSanitizerFunc{Name: "capfirst", Sanitizer: capFirst},
					OptionSanitizerFunc{Name: "capfirst", Sanitizer: doNothing},
				},
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.options...)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !sanitizersEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}
