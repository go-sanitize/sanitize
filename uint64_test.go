package sanitize

import (
	"reflect"
	"testing"
)

func Test_sanitizeUint64Field(t *testing.T) {
	s, _ := New()

	type TestUint64Struct struct {
		Field uint64 `san:"max=42,min=41"`
	}
	type TestUint64StructNegativeMUintag struct {
		Field uint64 `san:"max=41,min=-2"`
	}
	type TestUint64StructNegativeMaxTag struct {
		Field uint64 `san:"max=-2,min=42"`
	}
	type TestUint64StructBadMaxMin struct {
		Field uint64 `san:"max=41,min=42"`
	}
	type TestUint64StructBadMUintag struct {
		Field uint64 `san:"max=41,min=3.4"`
	}
	type TestUint64StructBadMaxTag struct {
		Field uint64 `san:"max=5.4,min=42"`
	}
	type TestUint64StructDef struct {
		Field uint64 `san:"def=43"`
	}
	type TestUint64StructPtr struct {
		Field *uint64 `san:"max=42,min=41,def=41"`
	}
	type TestUint64StructPtrBadDefMax struct {
		Field *uint64 `san:"max=42,def=43"`
	}
	type TestUint64StructPtrBadDefTag struct {
		Field *uint64 `san:"max=42,def=5.5"`
	}
	type TestUint64StructPtrBadDefMin struct {
		Field *uint64 `san:"min=41,def=40"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argUint0 := uint64(43)
	resUint0 := uint64(42)
	resUint1 := uint64(41)

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
			name: "Caps an Uint64 field on a struct with the san:max tag.",
			args: args{
				v: &TestUint64Struct{
					Field: 43,
				},
				idx: 0,
			},
			want: &TestUint64Struct{
				Field: 42,
			},
			wantErr: false,
		},
		{
			name: "Raises an Uint64 field on a struct with the san:min tag.",
			args: args{
				v: &TestUint64Struct{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint64Struct{
				Field: 41,
			},
			wantErr: false,
		},
		{
			name: "Returns an error if a san:min tag on a Uint64 field is below 0.",
			args: args{
				v: &TestUint64StructNegativeMUintag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint64StructNegativeMUintag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a Uint64 field is below 0.",
			args: args{
				v: &TestUint64StructNegativeMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint64StructNegativeMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:min tag on a Uint64 field is not numeric.",
			args: args{
				v: &TestUint64StructBadMUintag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint64StructBadMUintag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a Uint64 field is not numeric.",
			args: args{
				v: &TestUint64StructBadMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint64StructBadMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Default value does not affect an Uint64 field on a struct with the tag.",
			args: args{
				v:   &TestUint64StructDef{},
				idx: 0,
			},
			want:    &TestUint64StructDef{},
			wantErr: false,
		},
		{
			name: "Returns an error if the maximum value is smaller than the minimum on a struct with the tags.",
			args: args{
				v: &TestUint64StructBadMaxMin{
					Field: 2,
				},
				idx: 0,
			},
			want: &TestUint64StructBadMaxMin{
				Field: 2,
			},
			wantErr: true,
		},
		{
			name: "Caps an *Uint64 field on a struct with the san:max tag.",
			args: args{
				v: &TestUint64StructPtr{
					Field: &argUint0,
				},
				idx: 0,
			},
			want: &TestUint64StructPtr{
				Field: &resUint0,
			},
			wantErr: false,
		},
		{
			name: "Puts a default value for a *Uint64 field that was nil on a struct with the tag.",
			args: args{
				v: &TestUint64StructPtr{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestUint64StructPtr{
				Field: &resUint1,
			},
			wantErr: false,
		},
		{
			name: "Returns an error when the def component for a *Uint64 field is not numeric.",
			args: args{
				v: &TestUint64StructPtrBadDefTag{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestUint64StructPtrBadDefTag{
				Field: nil,
			},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the max component are both present, and the def is higher than the max for a *Uint64 field that was nil on a struct with the tag.",
			args: args{
				v: &TestUint64StructPtrBadDefMax{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestUint64StructPtrBadDefMax{},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the low component are both present, and the def is lower than the min for a *Uint64 field that was nil on a struct with the tag.",
			args: args{
				v: &TestUint64StructPtrBadDefMin{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestUint64StructPtrBadDefMin{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeUint64Field(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeUint64Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeUint64Field() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}
