package sanitize

import (
	"reflect"
	"testing"
)

func Test_sanitizeFloat32Field(t *testing.T) {
	s, _ := New()

	type TestFloat32Struct struct {
		Field float32 `san:"max=42.2,min=41.1"`
	}
	type TestFloat32StructNegativeMinTag struct {
		Field float32 `san:"max=41.1,min=-2"`
	}
	type TestFloat32StructNegativeMaxTag struct {
		Field float32 `san:"max=-2,min=42.2"`
	}
	type TestFloat32StructBadMaxMin struct {
		Field float32 `san:"max=41.1,min=42.2"`
	}
	type TestFloat32StructBadMinTag struct {
		Field float32 `san:"max=41.1,min=no"`
	}
	type TestFloat32StructBadMaxTag struct {
		Field float32 `san:"max=no,min=42.2"`
	}
	type TestFloat32StructDef struct {
		Field float32 `san:"def=43.3"`
	}
	type TestFloat32StructPtr struct {
		Field *float32 `san:"max=42.2,min=41.1,def=41.1"`
	}
	type TestFloat32StructPtrBadDefMax struct {
		Field *float32 `san:"max=42.2,def=43.3"`
	}
	type TestFloat32StructPtrBadDefTag struct {
		Field *float32 `san:"max=42.2,def=no"`
	}
	type TestFloat32StructPtrBadDefMin struct {
		Field *float32 `san:"min=41.1,def=40.0"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argInt0 := float32(43.3)
	resInt0 := float32(42.2)
	resInt1 := float32(41.1)

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
			name: "Caps an float32 field on a struct with the san:max tag.",
			args: args{
				v: &TestFloat32Struct{
					Field: 43.3,
				},
				idx: 0,
			},
			want: &TestFloat32Struct{
				Field: 42.2,
			},
			wantErr: false,
		},
		{
			name: "Raises an float32 field on a struct with the san:min tag.",
			args: args{
				v: &TestFloat32Struct{
					Field: 40.0,
				},
				idx: 0,
			},
			want: &TestFloat32Struct{
				Field: 41.1,
			},
			wantErr: false,
		},
		{
			name: "Returns an error if a san:min tag on a float32 field is below 0.",
			args: args{
				v: &TestFloat32StructNegativeMinTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestFloat32StructNegativeMinTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a float32 field is below 0.",
			args: args{
				v: &TestFloat32StructNegativeMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestFloat32StructNegativeMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:min tag on a float32 field is not numeric.",
			args: args{
				v: &TestFloat32StructBadMinTag{
					Field: 40.0,
				},
				idx: 0,
			},
			want: &TestFloat32StructBadMinTag{
				Field: 40.0,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a float32 field is not numeric.",
			args: args{
				v: &TestFloat32StructBadMaxTag{
					Field: 40.0,
				},
				idx: 0,
			},
			want: &TestFloat32StructBadMaxTag{
				Field: 40.0,
			},
			wantErr: true,
		},
		{
			name: "Default value does not affect an float32 field on a struct with the tag.",
			args: args{
				v:   &TestFloat32StructDef{},
				idx: 0,
			},
			want:    &TestFloat32StructDef{},
			wantErr: false,
		},
		{
			name: "Returns an error if the maximum value is smaller than the minimum on a struct with the tags.",
			args: args{
				v: &TestFloat32StructBadMaxMin{
					Field: 2.2,
				},
				idx: 0,
			},
			want: &TestFloat32StructBadMaxMin{
				Field: 2.2,
			},
			wantErr: true,
		},
		{
			name: "Caps an *float32 field on a struct with the san:max tag.",
			args: args{
				v: &TestFloat32StructPtr{
					Field: &argInt0,
				},
				idx: 0,
			},
			want: &TestFloat32StructPtr{
				Field: &resInt0,
			},
			wantErr: false,
		},
		{
			name: "Puts a default value for a *float32 field that was nil on a struct with the tag.",
			args: args{
				v: &TestFloat32StructPtr{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestFloat32StructPtr{
				Field: &resInt1,
			},
			wantErr: false,
		},
		{
			name: "Returns an error when the def component for a *float32 field is not numeric.",
			args: args{
				v: &TestFloat32StructPtrBadDefTag{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestFloat32StructPtrBadDefTag{
				Field: nil,
			},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the max component are both present, and the def is higher than the max for a *float32 field that was nil on a struct with the tag.",
			args: args{
				v: &TestFloat32StructPtrBadDefMax{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestFloat32StructPtrBadDefMax{},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the low component are both present, and the def is lower than the min for a *float32 field that was nil on a struct with the tag.",
			args: args{
				v: &TestFloat32StructPtrBadDefMin{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestFloat32StructPtrBadDefMin{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeFloat32Field(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeFloat32Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeFloat32Field() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}
