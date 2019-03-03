package sanitize

import (
	"reflect"
	"testing"
)

func Test_sanitizeUintField(t *testing.T) {
	s, _ := New()

	type TestUintStruct struct {
		Field uint `san:"max=42,min=41"`
	}
	type TestUintStructNegativeMUintag struct {
		Field uint `san:"max=41,min=-2"`
	}
	type TestUintStructNegativeMaxTag struct {
		Field uint `san:"max=-2,min=42"`
	}
	type TestUintStructBadMaxMin struct {
		Field uint `san:"max=41,min=42"`
	}
	type TestUintStructBadMUintag struct {
		Field uint `san:"max=41,min=3.4"`
	}
	type TestUintStructBadMaxTag struct {
		Field uint `san:"max=5.4,min=42"`
	}
	type TestUintStructDef struct {
		Field uint `san:"def=43"`
	}
	type TestUintStructPtr struct {
		Field *uint `san:"max=42,min=41,def=41"`
	}
	type TestUintStructPtrBadDefMax struct {
		Field *uint `san:"max=42,def=43"`
	}
	type TestUintStructPtrBadDefTag struct {
		Field *uint `san:"max=42,def=5.5"`
	}
	type TestUintStructPtrBadDefMin struct {
		Field *uint `san:"min=41,def=40"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argUint0 := uint(43)
	resUint0 := uint(42)
	resUint1 := uint(41)

	type args struct {
		v   interface{}
		idx int
	}
	tests := []struct {
		name    string
		args    args
		want    interface{}
		wantErr bool
	}{
		{
			name: "Caps an Uint field on a struct with the san:max tag.",
			args: args{
				v: &TestUintStruct{
					Field: 43,
				},
				idx: 0,
			},
			want: &TestUintStruct{
				Field: 42,
			},
			wantErr: false,
		},
		{
			name: "Raises an Uint field on a struct with the san:min tag.",
			args: args{
				v: &TestUintStruct{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUintStruct{
				Field: 41,
			},
			wantErr: false,
		},
		{
			name: "Returns an error if a san:min tag on a Uint field is below 0.",
			args: args{
				v: &TestUintStructNegativeMUintag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUintStructNegativeMUintag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a Uint field is below 0.",
			args: args{
				v: &TestUintStructNegativeMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUintStructNegativeMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:min tag on a Uint field is not numeric.",
			args: args{
				v: &TestUintStructBadMUintag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUintStructBadMUintag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a Uint field is not numeric.",
			args: args{
				v: &TestUintStructBadMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUintStructBadMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Default value does not affect an Uint field on a struct with the tag.",
			args: args{
				v:   &TestUintStructDef{},
				idx: 0,
			},
			want:    &TestUintStructDef{},
			wantErr: false,
		},
		{
			name: "Returns an error if the maximum value is smaller than the minimum on a struct with the tags.",
			args: args{
				v: &TestUintStructBadMaxMin{
					Field: 2,
				},
				idx: 0,
			},
			want: &TestUintStructBadMaxMin{
				Field: 2,
			},
			wantErr: true,
		},
		{
			name: "Caps an *Uint field on a struct with the san:max tag.",
			args: args{
				v: &TestUintStructPtr{
					Field: &argUint0,
				},
				idx: 0,
			},
			want: &TestUintStructPtr{
				Field: &resUint0,
			},
			wantErr: false,
		},
		{
			name: "Puts a default value for a *Uint field that was nil on a struct with the tag.",
			args: args{
				v: &TestUintStructPtr{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestUintStructPtr{
				Field: &resUint1,
			},
			wantErr: false,
		},
		{
			name: "Returns an error when the def component for a *Uint field is not numeric.",
			args: args{
				v: &TestUintStructPtrBadDefTag{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestUintStructPtrBadDefTag{
				Field: nil,
			},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the max component are both present, and the def is higher than the max for a *Uint field that was nil on a struct with the tag.",
			args: args{
				v: &TestUintStructPtrBadDefMax{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestUintStructPtrBadDefMax{},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the low component are both present, and the def is lower than the min for a *Uint field that was nil on a struct with the tag.",
			args: args{
				v: &TestUintStructPtrBadDefMin{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestUintStructPtrBadDefMin{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeUintField(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeUintField() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeUintField() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}
