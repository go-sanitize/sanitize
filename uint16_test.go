package sanitize

import (
	"reflect"
	"testing"
)

func Test_sanitizeUint16Field(t *testing.T) {
	s, _ := New()

	type TestUint16Struct struct {
		Field uint16 `san:"max=42,min=41"`
	}
	type TestUint16StructNegativeMUintag struct {
		Field uint16 `san:"max=41,min=-2"`
	}
	type TestUint16StructNegativeMaxTag struct {
		Field uint16 `san:"max=-2,min=42"`
	}
	type TestUint16StructBadMaxMin struct {
		Field uint16 `san:"max=41,min=42"`
	}
	type TestUint16StructBadMUintag struct {
		Field uint16 `san:"max=41,min=3.4"`
	}
	type TestUint16StructBadMaxTag struct {
		Field uint16 `san:"max=5.4,min=42"`
	}
	type TestUint16StructDef struct {
		Field uint16 `san:"def=43"`
	}
	type TestUint16StructPtr struct {
		Field *uint16 `san:"max=42,min=41,def=41"`
	}
	type TestUint16StructPtrBadDefMax struct {
		Field *uint16 `san:"max=42,def=43"`
	}
	type TestUint16StructPtrBadDefTag struct {
		Field *uint16 `san:"max=42,def=5.5"`
	}
	type TestUint16StructPtrBadDefMin struct {
		Field *uint16 `san:"min=41,def=40"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argUint0 := uint16(43)
	resUint0 := uint16(42)
	resUint1 := uint16(41)

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
			name: "Caps an Uint16 field on a struct with the san:max tag.",
			args: args{
				v: &TestUint16Struct{
					Field: 43,
				},
				idx: 0,
			},
			want: &TestUint16Struct{
				Field: 42,
			},
			wantErr: false,
		},
		{
			name: "Raises an Uint16 field on a struct with the san:min tag.",
			args: args{
				v: &TestUint16Struct{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint16Struct{
				Field: 41,
			},
			wantErr: false,
		},
		{
			name: "Returns an error if a san:min tag on a Uint16 field is below 0.",
			args: args{
				v: &TestUint16StructNegativeMUintag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint16StructNegativeMUintag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a Uint16 field is below 0.",
			args: args{
				v: &TestUint16StructNegativeMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint16StructNegativeMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:min tag on a Uint16 field is not numeric.",
			args: args{
				v: &TestUint16StructBadMUintag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint16StructBadMUintag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a Uint16 field is not numeric.",
			args: args{
				v: &TestUint16StructBadMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint16StructBadMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Default value does not affect an Uint16 field on a struct with the tag.",
			args: args{
				v:   &TestUint16StructDef{},
				idx: 0,
			},
			want:    &TestUint16StructDef{},
			wantErr: false,
		},
		{
			name: "Returns an error if the maximum value is smaller than the minimum on a struct with the tags.",
			args: args{
				v: &TestUint16StructBadMaxMin{
					Field: 2,
				},
				idx: 0,
			},
			want: &TestUint16StructBadMaxMin{
				Field: 2,
			},
			wantErr: true,
		},
		{
			name: "Caps an *Uint16 field on a struct with the san:max tag.",
			args: args{
				v: &TestUint16StructPtr{
					Field: &argUint0,
				},
				idx: 0,
			},
			want: &TestUint16StructPtr{
				Field: &resUint0,
			},
			wantErr: false,
		},
		{
			name: "Puts a default value for a *Uint16 field that was nil on a struct with the tag.",
			args: args{
				v: &TestUint16StructPtr{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestUint16StructPtr{
				Field: &resUint1,
			},
			wantErr: false,
		},
		{
			name: "Returns an error when the def component for a *Uint16 field is not numeric.",
			args: args{
				v: &TestUint16StructPtrBadDefTag{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestUint16StructPtrBadDefTag{
				Field: nil,
			},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the max component are both present, and the def is higher than the max for a *Uint16 field that was nil on a struct with the tag.",
			args: args{
				v: &TestUint16StructPtrBadDefMax{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestUint16StructPtrBadDefMax{},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the low component are both present, and the def is lower than the min for a *Uint16 field that was nil on a struct with the tag.",
			args: args{
				v: &TestUint16StructPtrBadDefMin{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestUint16StructPtrBadDefMin{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeUint16Field(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeUint16Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeUint16Field() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}
