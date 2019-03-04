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
	type TestUintStructNegativeMinTag struct {
		Field uint `san:"max=41,min=-2"`
	}
	type TestUintStructNegativeMaxTag struct {
		Field uint `san:"max=-2,min=42"`
	}
	type TestUintStructBadMaxMin struct {
		Field uint `san:"max=41,min=42"`
	}
	type TestUintStructBadMinTag struct {
		Field uint `san:"max=41,min=no"`
	}
	type TestUintStructBadMaxTag struct {
		Field uint `san:"max=no,min=42"`
	}
	type TestUintStructDef struct {
		Field uint `san:"def=43"`
	}
	type TestUintStructPtr struct {
		Field *uint `san:"max=42,min=41"`
	}
	type TestUintStructPtrDef struct {
		Field *uint `san:"max=42,min=41,def=41"`
	}
	type TestUintStructPtrBadDefMax struct {
		Field *uint `san:"max=42,def=43"`
	}
	type TestUintStructPtrBadDefTag struct {
		Field *uint `san:"max=42,def=no"`
	}
	type TestUintStructPtrBadDefMin struct {
		Field *uint `san:"min=41,def=40"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argInt0 := uint(43)
	resInt0 := uint(42)
	resInt1 := uint(41)

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
			name: "Caps an uint field on a struct with the san:max tag.",
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
			name: "Raises an uint field on a struct with the san:min tag.",
			args: args{
				v: &TestUintStruct{
					Field: 40.0,
				},
				idx: 0,
			},
			want: &TestUintStruct{
				Field: 41,
			},
			wantErr: false,
		},
		{
			name: "Returns an error if a san:min tag on a uint field is below 0.",
			args: args{
				v: &TestUintStructNegativeMinTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUintStructNegativeMinTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a uint field is below 0.",
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
			name: "Returns an error if a san:min tag on a uint field is not numeric.",
			args: args{
				v: &TestUintStructBadMinTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUintStructBadMinTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a uint field is not numeric.",
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
			name: "Default value does not affect an uint field on a struct with the tag.",
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
			name: "Ignores a nil *uint field that was nil on a struct without a def tag.",
			args: args{
				v: &TestUintStructPtr{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestUintStructPtr{
				Field: nil,
			},
			wantErr: false,
		},
		{
			name: "Caps an *uint field on a struct with the san:max tag.",
			args: args{
				v: &TestUintStructPtrDef{
					Field: &argInt0,
				},
				idx: 0,
			},
			want: &TestUintStructPtrDef{
				Field: &resInt0,
			},
			wantErr: false,
		},
		{
			name: "Puts a default value for a *uint field that was nil on a struct with the tag.",
			args: args{
				v: &TestUintStructPtrDef{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestUintStructPtrDef{
				Field: &resInt1,
			},
			wantErr: false,
		},
		{
			name: "Returns an error when the def component for a *uint field is not numeric.",
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
			name: "Returns an error when the def component and the max component are both present, and the def is higher than the max for a *uint field that was nil on a struct with the tag.",
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
			name: "Returns an error when the def component and the low component are both present, and the def is lower than the min for a *uint field that was nil on a struct with the tag.",
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

func Test_sanitizeUintField_Slice(t *testing.T) {
	s, _ := New()

	type TestStrStructUintSli struct {
		Field []uint `san:"max=50,min=40"`
	}
	type TestStrStructUintPtrSli struct {
		Field []*uint `san:"max=50,min=40"`
	}
	type TestStrStructUintPtrSliDef struct {
		Field []*uint `san:"max=50,min=40,def=42"`
	}
	type TestStrStructUintSliPtr struct {
		Field *[]uint `san:"max=50,min=40"`
	}
	type TestStrStructUintPtrSliPtr struct {
		Field *[]*uint `san:"max=50,min=40"`
	}
	type TestStrStructUintPtrSliPtrDef struct {
		Field *[]*uint `san:"max=50,min=40,def=42"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argUint0 := uint(30)
	resUint0 := uint(40)
	argUint1 := uint(45)
	resUint1 := uint(45)
	argUint2 := uint(60)
	resUint2 := uint(50)
	resUint3 := uint(42)
	argUint4 := uint(30)
	resUint4 := uint(40)
	argUint5 := uint(45)
	resUint5 := uint(45)
	argUint6 := uint(60)
	resUint6 := uint(50)
	resUint7 := uint(42)

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
			name: "Applies tags to a non-empty []uint field.",
			args: args{
				v: &TestStrStructUintSli{
					Field: []uint{
						30,
						45,
						60,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUintSli{
				Field: []uint{
					40,
					45,
					50,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to an empty []uint field.",
			args: args{
				v:   &TestStrStructUintSli{},
				idx: 0,
			},
			want:    &TestStrStructUintSli{},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty []*uint field.",
			args: args{
				v: &TestStrStructUintPtrSli{
					Field: []*uint{
						&argUint0,
						&argUint1,
						&argUint2,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUintPtrSli{
				Field: []*uint{
					&resUint0,
					&resUint1,
					&resUint2,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty []*uint field.",
			args: args{
				v: &TestStrStructUintPtrSli{
					Field: []*uint{
						nil,
						nil,
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUintPtrSli{
				Field: []*uint{
					nil,
					nil,
					nil,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags (with default) to a non-empty []*uint field.",
			args: args{
				v: &TestStrStructUintPtrSliDef{
					Field: []*uint{
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUintPtrSliDef{
				Field: []*uint{
					&resUint3,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]uint field.",
			args: args{
				v: &TestStrStructUintSliPtr{
					Field: &[]uint{
						30,
						45,
						60,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUintSliPtr{
				Field: &[]uint{
					40,
					45,
					50,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to an empty *[]uint field.",
			args: args{
				v:   &TestStrStructUintSliPtr{},
				idx: 0,
			},
			want:    &TestStrStructUintSliPtr{},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]*uint field.",
			args: args{
				v: &TestStrStructUintPtrSliPtr{
					Field: &[]*uint{
						&argUint4,
						&argUint5,
						&argUint6,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUintPtrSliPtr{
				Field: &[]*uint{
					&resUint4,
					&resUint5,
					&resUint6,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]*uint field.",
			args: args{
				v: &TestStrStructUintPtrSliPtr{
					Field: &[]*uint{
						nil,
						nil,
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUintPtrSliPtr{
				Field: &[]*uint{
					nil,
					nil,
					nil,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags (with default) to a non-empty *[]*uint field.",
			args: args{
				v: &TestStrStructUintPtrSliPtrDef{
					Field: &[]*uint{
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUintPtrSliPtrDef{
				Field: &[]*uint{
					&resUint7,
				},
			},
			wantErr: false,
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
