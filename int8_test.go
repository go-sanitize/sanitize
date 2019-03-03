package sanitize

import (
	"reflect"
	"testing"
)

func Test_sanitizeInt8Field(t *testing.T) {
	s, _ := New()

	type TestInt8Struct struct {
		Field int8 `san:"max=42,min=41"`
	}
	type TestInt8StructNegativeMinTag struct {
		Field int8 `san:"max=41,min=-2"`
	}
	type TestInt8StructNegativeMaxTag struct {
		Field int8 `san:"max=-2,min=42"`
	}
	type TestInt8StructBadMaxMin struct {
		Field int8 `san:"max=41,min=42"`
	}
	type TestInt8StructBadMinTag struct {
		Field int8 `san:"max=41,min=3.4"`
	}
	type TestInt8StructBadMaxTag struct {
		Field int8 `san:"max=5.4,min=42"`
	}
	type TestInt8StructDef struct {
		Field int8 `san:"def=43"`
	}
	type TestInt8StructPtr struct {
		Field *int8 `san:"max=42,min=41,def=41"`
	}
	type TestInt8StructPtrBadDefMax struct {
		Field *int8 `san:"max=42,def=43"`
	}
	type TestInt8StructPtrBadDefTag struct {
		Field *int8 `san:"max=42,def=5.5"`
	}
	type TestInt8StructPtrBadDefMin struct {
		Field *int8 `san:"min=41,def=40"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argInt0 := int8(43)
	resInt0 := int8(42)
	resInt1 := int8(41)

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
			name: "Caps an int8 field on a struct with the san:max tag.",
			args: args{
				v: &TestInt8Struct{
					Field: 43,
				},
				idx: 0,
			},
			want: &TestInt8Struct{
				Field: 42,
			},
			wantErr: false,
		},
		{
			name: "Raises an int8 field on a struct with the san:min tag.",
			args: args{
				v: &TestInt8Struct{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestInt8Struct{
				Field: 41,
			},
			wantErr: false,
		},
		{
			name: "Returns an error if a san:min tag on a int8 field is below 0.",
			args: args{
				v: &TestInt8StructNegativeMinTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestInt8StructNegativeMinTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a int8 field is below 0.",
			args: args{
				v: &TestInt8StructNegativeMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestInt8StructNegativeMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:min tag on a int8 field is not numeric.",
			args: args{
				v: &TestInt8StructBadMinTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestInt8StructBadMinTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a int8 field is not numeric.",
			args: args{
				v: &TestInt8StructBadMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestInt8StructBadMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Default value does not affect an int8 field on a struct with the tag.",
			args: args{
				v:   &TestInt8StructDef{},
				idx: 0,
			},
			want:    &TestInt8StructDef{},
			wantErr: false,
		},
		{
			name: "Returns an error if the maximum value is smaller than the minimum on a struct with the tags.",
			args: args{
				v: &TestInt8StructBadMaxMin{
					Field: 2,
				},
				idx: 0,
			},
			want: &TestInt8StructBadMaxMin{
				Field: 2,
			},
			wantErr: true,
		},
		{
			name: "Caps an *int8 field on a struct with the san:max tag.",
			args: args{
				v: &TestInt8StructPtr{
					Field: &argInt0,
				},
				idx: 0,
			},
			want: &TestInt8StructPtr{
				Field: &resInt0,
			},
			wantErr: false,
		},
		{
			name: "Puts a default value for a *int8 field that was nil on a struct with the tag.",
			args: args{
				v: &TestInt8StructPtr{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestInt8StructPtr{
				Field: &resInt1,
			},
			wantErr: false,
		},
		{
			name: "Returns an error when the def component for a *int8 field is not numeric.",
			args: args{
				v: &TestInt8StructPtrBadDefTag{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestInt8StructPtrBadDefTag{
				Field: nil,
			},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the max component are both present, and the def is higher than the max for a *int8 field that was nil on a struct with the tag.",
			args: args{
				v: &TestInt8StructPtrBadDefMax{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestInt8StructPtrBadDefMax{},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the low component are both present, and the def is lower than the min for a *int8 field that was nil on a struct with the tag.",
			args: args{
				v: &TestInt8StructPtrBadDefMin{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestInt8StructPtrBadDefMin{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeInt8Field(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeInt8Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeInt8Field() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}
