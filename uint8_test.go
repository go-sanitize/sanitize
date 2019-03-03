package sanitize

import (
	"reflect"
	"testing"
)

func Test_sanitizeUint8Field(t *testing.T) {
	s, _ := New()

	type TestUint8Struct struct {
		Field uint8 `san:"max=42,min=41"`
	}
	type TestUint8StructNegativeMUintag struct {
		Field uint8 `san:"max=41,min=-2"`
	}
	type TestUint8StructNegativeMaxTag struct {
		Field uint8 `san:"max=-2,min=42"`
	}
	type TestUint8StructBadMaxMin struct {
		Field uint8 `san:"max=41,min=42"`
	}
	type TestUint8StructBadMUintag struct {
		Field uint8 `san:"max=41,min=3.4"`
	}
	type TestUint8StructBadMaxTag struct {
		Field uint8 `san:"max=5.4,min=42"`
	}
	type TestUint8StructDef struct {
		Field uint8 `san:"def=43"`
	}
	type TestUint8StructPtr struct {
		Field *uint8 `san:"max=42,min=41,def=41"`
	}
	type TestUint8StructPtrBadDefMax struct {
		Field *uint8 `san:"max=42,def=43"`
	}
	type TestUint8StructPtrBadDefTag struct {
		Field *uint8 `san:"max=42,def=5.5"`
	}
	type TestUint8StructPtrBadDefMin struct {
		Field *uint8 `san:"min=41,def=40"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argUint0 := uint8(43)
	resUint0 := uint8(42)
	resUint1 := uint8(41)

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
			name: "Caps an Uint8 field on a struct with the san:max tag.",
			args: args{
				v: &TestUint8Struct{
					Field: 43,
				},
				idx: 0,
			},
			want: &TestUint8Struct{
				Field: 42,
			},
			wantErr: false,
		},
		{
			name: "Raises an Uint8 field on a struct with the san:min tag.",
			args: args{
				v: &TestUint8Struct{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint8Struct{
				Field: 41,
			},
			wantErr: false,
		},
		{
			name: "Returns an error if a san:min tag on a Uint8 field is below 0.",
			args: args{
				v: &TestUint8StructNegativeMUintag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint8StructNegativeMUintag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a Uint8 field is below 0.",
			args: args{
				v: &TestUint8StructNegativeMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint8StructNegativeMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:min tag on a Uint8 field is not numeric.",
			args: args{
				v: &TestUint8StructBadMUintag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint8StructBadMUintag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a Uint8 field is not numeric.",
			args: args{
				v: &TestUint8StructBadMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint8StructBadMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Default value does not affect an Uint8 field on a struct with the tag.",
			args: args{
				v:   &TestUint8StructDef{},
				idx: 0,
			},
			want:    &TestUint8StructDef{},
			wantErr: false,
		},
		{
			name: "Returns an error if the maximum value is smaller than the minimum on a struct with the tags.",
			args: args{
				v: &TestUint8StructBadMaxMin{
					Field: 2,
				},
				idx: 0,
			},
			want: &TestUint8StructBadMaxMin{
				Field: 2,
			},
			wantErr: true,
		},
		{
			name: "Caps an *Uint8 field on a struct with the san:max tag.",
			args: args{
				v: &TestUint8StructPtr{
					Field: &argUint0,
				},
				idx: 0,
			},
			want: &TestUint8StructPtr{
				Field: &resUint0,
			},
			wantErr: false,
		},
		{
			name: "Puts a default value for a *Uint8 field that was nil on a struct with the tag.",
			args: args{
				v: &TestUint8StructPtr{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestUint8StructPtr{
				Field: &resUint1,
			},
			wantErr: false,
		},
		{
			name: "Returns an error when the def component for a *Uint8 field is not numeric.",
			args: args{
				v: &TestUint8StructPtrBadDefTag{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestUint8StructPtrBadDefTag{
				Field: nil,
			},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the max component are both present, and the def is higher than the max for a *Uint8 field that was nil on a struct with the tag.",
			args: args{
				v: &TestUint8StructPtrBadDefMax{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestUint8StructPtrBadDefMax{},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the low component are both present, and the def is lower than the min for a *Uint8 field that was nil on a struct with the tag.",
			args: args{
				v: &TestUint8StructPtrBadDefMin{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestUint8StructPtrBadDefMin{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeUint8Field(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeUint8Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeUint8Field() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}
