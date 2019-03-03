package sanitize

import (
	"reflect"
	"testing"
)

func Test_sanitizeIntField(t *testing.T) {
	s, _ := New()

	type TestIntStruct struct {
		Field int `san:"max=42,min=41"`
	}
	type TestIntStructNegativeMinTag struct {
		Field int `san:"max=41,min=-2"`
	}
	type TestIntStructNegativeMaxTag struct {
		Field int `san:"max=-2,min=42"`
	}
	type TestIntStructBadMaxMin struct {
		Field int `san:"max=41,min=42"`
	}
	type TestIntStructBadMinTag struct {
		Field int `san:"max=41,min=3.4"`
	}
	type TestIntStructBadMaxTag struct {
		Field int `san:"max=5.4,min=42"`
	}
	type TestIntStructDef struct {
		Field int `san:"def=43"`
	}
	type TestIntStructPtr struct {
		Field *int `san:"max=42,min=41,def=41"`
	}
	type TestIntStructPtrBadDefMax struct {
		Field *int `san:"max=42,def=43"`
	}
	type TestIntStructPtrBadDefTag struct {
		Field *int `san:"max=42,def=5.5"`
	}
	type TestIntStructPtrBadDefMin struct {
		Field *int `san:"min=41,def=40"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argInt0 := int(43)
	resInt0 := int(42)
	resInt1 := int(41)

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
			name: "Caps an int field on a struct with the san:max tag.",
			args: args{
				v: &TestIntStruct{
					Field: 43,
				},
				idx: 0,
			},
			want: &TestIntStruct{
				Field: 42,
			},
			wantErr: false,
		},
		{
			name: "Raises an int field on a struct with the san:min tag.",
			args: args{
				v: &TestIntStruct{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestIntStruct{
				Field: 41,
			},
			wantErr: false,
		},
		{
			name: "Returns an error if a san:min tag on a int field is below 0.",
			args: args{
				v: &TestIntStructNegativeMinTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestIntStructNegativeMinTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a int field is below 0.",
			args: args{
				v: &TestIntStructNegativeMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestIntStructNegativeMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:min tag on a int field is not numeric.",
			args: args{
				v: &TestIntStructBadMinTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestIntStructBadMinTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a int field is not numeric.",
			args: args{
				v: &TestIntStructBadMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestIntStructBadMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Default value does not affect an int field on a struct with the tag.",
			args: args{
				v:   &TestIntStructDef{},
				idx: 0,
			},
			want:    &TestIntStructDef{},
			wantErr: false,
		},
		{
			name: "Returns an error if the maximum value is smaller than the minimum on a struct with the tags.",
			args: args{
				v: &TestIntStructBadMaxMin{
					Field: 2,
				},
				idx: 0,
			},
			want: &TestIntStructBadMaxMin{
				Field: 2,
			},
			wantErr: true,
		},
		{
			name: "Caps an *int field on a struct with the san:max tag.",
			args: args{
				v: &TestIntStructPtr{
					Field: &argInt0,
				},
				idx: 0,
			},
			want: &TestIntStructPtr{
				Field: &resInt0,
			},
			wantErr: false,
		},
		{
			name: "Puts a default value for a *int field that was nil on a struct with the tag.",
			args: args{
				v: &TestIntStructPtr{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestIntStructPtr{
				Field: &resInt1,
			},
			wantErr: false,
		},
		{
			name: "Returns an error when the def component for a *int field is not numeric.",
			args: args{
				v: &TestIntStructPtrBadDefTag{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestIntStructPtrBadDefTag{
				Field: nil,
			},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the max component are both present, and the def is higher than the max for a *int field that was nil on a struct with the tag.",
			args: args{
				v: &TestIntStructPtrBadDefMax{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestIntStructPtrBadDefMax{},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the low component are both present, and the def is lower than the min for a *int field that was nil on a struct with the tag.",
			args: args{
				v: &TestIntStructPtrBadDefMin{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestIntStructPtrBadDefMin{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeIntField(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeIntField() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeIntField() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}
