package sanitize

import (
	"reflect"
	"testing"
)

func Test_sanitizeInt32Field(t *testing.T) {
	s, _ := New()

	type TestInt32Struct struct {
		Field int32 `san:"max=42,min=41"`
	}
	type TestInt32StructNegativeMinTag struct {
		Field int32 `san:"max=41,min=-2"`
	}
	type TestInt32StructNegativeMaxTag struct {
		Field int32 `san:"max=-2,min=42"`
	}
	type TestInt32StructBadMaxMin struct {
		Field int32 `san:"max=41,min=42"`
	}
	type TestInt32StructBadMinTag struct {
		Field int32 `san:"max=41,min=3.4"`
	}
	type TestInt32StructBadMaxTag struct {
		Field int32 `san:"max=5.4,min=42"`
	}
	type TestInt32StructDef struct {
		Field int32 `san:"def=43"`
	}
	type TestInt32StructPtr struct {
		Field *int32 `san:"max=42,min=41,def=41"`
	}
	type TestInt32StructPtrBadDefMax struct {
		Field *int32 `san:"max=42,def=43"`
	}
	type TestInt32StructPtrBadDefTag struct {
		Field *int32 `san:"max=42,def=5.5"`
	}
	type TestInt32StructPtrBadDefMin struct {
		Field *int32 `san:"min=41,def=40"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argInt0 := int32(43)
	resInt0 := int32(42)
	resInt1 := int32(41)

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
			name: "Caps an int32 field on a struct with the san:max tag.",
			args: args{
				v: &TestInt32Struct{
					Field: 43,
				},
				idx: 0,
			},
			want: &TestInt32Struct{
				Field: 42,
			},
			wantErr: false,
		},
		{
			name: "Raises an int32 field on a struct with the san:min tag.",
			args: args{
				v: &TestInt32Struct{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestInt32Struct{
				Field: 41,
			},
			wantErr: false,
		},
		{
			name: "Returns an error if a san:min tag on a int32 field is below 0.",
			args: args{
				v: &TestInt32StructNegativeMinTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestInt32StructNegativeMinTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a int32 field is below 0.",
			args: args{
				v: &TestInt32StructNegativeMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestInt32StructNegativeMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:min tag on a int32 field is not numeric.",
			args: args{
				v: &TestInt32StructBadMinTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestInt32StructBadMinTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a int32 field is not numeric.",
			args: args{
				v: &TestInt32StructBadMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestInt32StructBadMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Default value does not affect an int32 field on a struct with the tag.",
			args: args{
				v:   &TestInt32StructDef{},
				idx: 0,
			},
			want:    &TestInt32StructDef{},
			wantErr: false,
		},
		{
			name: "Returns an error if the maximum value is smaller than the minimum on a struct with the tags.",
			args: args{
				v: &TestInt32StructBadMaxMin{
					Field: 2,
				},
				idx: 0,
			},
			want: &TestInt32StructBadMaxMin{
				Field: 2,
			},
			wantErr: true,
		},
		{
			name: "Caps an *int32 field on a struct with the san:max tag.",
			args: args{
				v: &TestInt32StructPtr{
					Field: &argInt0,
				},
				idx: 0,
			},
			want: &TestInt32StructPtr{
				Field: &resInt0,
			},
			wantErr: false,
		},
		{
			name: "Puts a default value for a *int32 field that was nil on a struct with the tag.",
			args: args{
				v: &TestInt32StructPtr{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestInt32StructPtr{
				Field: &resInt1,
			},
			wantErr: false,
		},
		{
			name: "Returns an error when the def component for a *int32 field is not numeric.",
			args: args{
				v: &TestInt32StructPtrBadDefTag{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestInt32StructPtrBadDefTag{
				Field: nil,
			},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the max component are both present, and the def is higher than the max for a *int32 field that was nil on a struct with the tag.",
			args: args{
				v: &TestInt32StructPtrBadDefMax{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestInt32StructPtrBadDefMax{},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the low component are both present, and the def is lower than the min for a *int32 field that was nil on a struct with the tag.",
			args: args{
				v: &TestInt32StructPtrBadDefMin{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestInt32StructPtrBadDefMin{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeInt32Field(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeInt32Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeInt32Field() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}
