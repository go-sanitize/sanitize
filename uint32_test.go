package sanitize

import (
	"reflect"
	"testing"
)

func Test_sanitizeUint32Field(t *testing.T) {
	s, _ := New()

	type TestUint32Struct struct {
		Field uint32 `san:"max=42,min=41"`
	}
	type TestUint32StructNegativeMUintag struct {
		Field uint32 `san:"max=41,min=-2"`
	}
	type TestUint32StructNegativeMaxTag struct {
		Field uint32 `san:"max=-2,min=42"`
	}
	type TestUint32StructBadMaxMin struct {
		Field uint32 `san:"max=41,min=42"`
	}
	type TestUint32StructBadMUintag struct {
		Field uint32 `san:"max=41,min=3.4"`
	}
	type TestUint32StructBadMaxTag struct {
		Field uint32 `san:"max=5.4,min=42"`
	}
	type TestUint32StructDef struct {
		Field uint32 `san:"def=43"`
	}
	type TestUint32StructPtr struct {
		Field *uint32 `san:"max=42,min=41,def=41"`
	}
	type TestUint32StructPtrBadDefMax struct {
		Field *uint32 `san:"max=42,def=43"`
	}
	type TestUint32StructPtrBadDefTag struct {
		Field *uint32 `san:"max=42,def=5.5"`
	}
	type TestUint32StructPtrBadDefMin struct {
		Field *uint32 `san:"min=41,def=40"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argUint0 := uint32(43)
	resUint0 := uint32(42)
	resUint1 := uint32(41)

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
			name: "Caps an Uint32 field on a struct with the san:max tag.",
			args: args{
				v: &TestUint32Struct{
					Field: 43,
				},
				idx: 0,
			},
			want: &TestUint32Struct{
				Field: 42,
			},
			wantErr: false,
		},
		{
			name: "Raises an Uint32 field on a struct with the san:min tag.",
			args: args{
				v: &TestUint32Struct{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint32Struct{
				Field: 41,
			},
			wantErr: false,
		},
		{
			name: "Returns an error if a san:min tag on a Uint32 field is below 0.",
			args: args{
				v: &TestUint32StructNegativeMUintag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint32StructNegativeMUintag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a Uint32 field is below 0.",
			args: args{
				v: &TestUint32StructNegativeMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint32StructNegativeMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:min tag on a Uint32 field is not numeric.",
			args: args{
				v: &TestUint32StructBadMUintag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint32StructBadMUintag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a Uint32 field is not numeric.",
			args: args{
				v: &TestUint32StructBadMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint32StructBadMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Default value does not affect an Uint32 field on a struct with the tag.",
			args: args{
				v:   &TestUint32StructDef{},
				idx: 0,
			},
			want:    &TestUint32StructDef{},
			wantErr: false,
		},
		{
			name: "Returns an error if the maximum value is smaller than the minimum on a struct with the tags.",
			args: args{
				v: &TestUint32StructBadMaxMin{
					Field: 2,
				},
				idx: 0,
			},
			want: &TestUint32StructBadMaxMin{
				Field: 2,
			},
			wantErr: true,
		},
		{
			name: "Caps an *Uint32 field on a struct with the san:max tag.",
			args: args{
				v: &TestUint32StructPtr{
					Field: &argUint0,
				},
				idx: 0,
			},
			want: &TestUint32StructPtr{
				Field: &resUint0,
			},
			wantErr: false,
		},
		{
			name: "Puts a default value for a *Uint32 field that was nil on a struct with the tag.",
			args: args{
				v: &TestUint32StructPtr{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestUint32StructPtr{
				Field: &resUint1,
			},
			wantErr: false,
		},
		{
			name: "Returns an error when the def component for a *Uint32 field is not numeric.",
			args: args{
				v: &TestUint32StructPtrBadDefTag{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestUint32StructPtrBadDefTag{
				Field: nil,
			},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the max component are both present, and the def is higher than the max for a *Uint32 field that was nil on a struct with the tag.",
			args: args{
				v: &TestUint32StructPtrBadDefMax{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestUint32StructPtrBadDefMax{},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the low component are both present, and the def is lower than the min for a *Uint32 field that was nil on a struct with the tag.",
			args: args{
				v: &TestUint32StructPtrBadDefMin{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestUint32StructPtrBadDefMin{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeUint32Field(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeUint32Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeUint32Field() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}
