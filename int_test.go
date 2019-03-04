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
		Field int `san:"max=41,min=no"`
	}
	type TestIntStructBadMaxTag struct {
		Field int `san:"max=no,min=42"`
	}
	type TestIntStructDef struct {
		Field int `san:"def=43"`
	}
	type TestIntStructPtr struct {
		Field *int `san:"max=42,min=41"`
	}
	type TestIntStructPtrDef struct {
		Field *int `san:"max=42,min=41,def=41"`
	}
	type TestIntStructPtrBadDefMax struct {
		Field *int `san:"max=42,def=43"`
	}
	type TestIntStructPtrBadDefTag struct {
		Field *int `san:"max=42,def=no"`
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
					Field: 40.0,
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
			name: "Ignores a nil *int field that was nil on a struct without a def tag.",
			args: args{
				v: &TestIntStructPtr{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestIntStructPtr{
				Field: nil,
			},
			wantErr: false,
		},
		{
			name: "Caps an *int field on a struct with the san:max tag.",
			args: args{
				v: &TestIntStructPtrDef{
					Field: &argInt0,
				},
				idx: 0,
			},
			want: &TestIntStructPtrDef{
				Field: &resInt0,
			},
			wantErr: false,
		},
		{
			name: "Puts a default value for a *int field that was nil on a struct with the tag.",
			args: args{
				v: &TestIntStructPtrDef{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestIntStructPtrDef{
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

func Test_sanitizeIntField_Slice(t *testing.T) {
	s, _ := New()

	type TestStrStructIntSli struct {
		Field []int `san:"max=50,min=40"`
	}
	type TestStrStructIntPtrSli struct {
		Field []*int `san:"max=50,min=40"`
	}
	type TestStrStructIntPtrSliDef struct {
		Field []*int `san:"max=50,min=40,def=42"`
	}
	type TestStrStructIntSliPtr struct {
		Field *[]int `san:"max=50,min=40"`
	}
	type TestStrStructIntPtrSliPtr struct {
		Field *[]*int `san:"max=50,min=40"`
	}
	type TestStrStructIntPtrSliPtrDef struct {
		Field *[]*int `san:"max=50,min=40,def=42"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argInt0 := int(30)
	resInt0 := int(40)
	argInt1 := int(45)
	resInt1 := int(45)
	argInt2 := int(60)
	resInt2 := int(50)
	resInt3 := int(42)
	argInt4 := int(30)
	resInt4 := int(40)
	argInt5 := int(45)
	resInt5 := int(45)
	argInt6 := int(60)
	resInt6 := int(50)
	resInt7 := int(42)

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
			name: "Applies tags to a non-empty []int field.",
			args: args{
				v: &TestStrStructIntSli{
					Field: []int{
						30,
						45,
						60,
					},
				},
				idx: 0,
			},
			want: &TestStrStructIntSli{
				Field: []int{
					40,
					45,
					50,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to an empty []int field.",
			args: args{
				v:   &TestStrStructIntSli{},
				idx: 0,
			},
			want:    &TestStrStructIntSli{},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty []*int field.",
			args: args{
				v: &TestStrStructIntPtrSli{
					Field: []*int{
						&argInt0,
						&argInt1,
						&argInt2,
					},
				},
				idx: 0,
			},
			want: &TestStrStructIntPtrSli{
				Field: []*int{
					&resInt0,
					&resInt1,
					&resInt2,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty []*int field.",
			args: args{
				v: &TestStrStructIntPtrSli{
					Field: []*int{
						nil,
						nil,
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructIntPtrSli{
				Field: []*int{
					nil,
					nil,
					nil,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags (with default) to a non-empty []*int field.",
			args: args{
				v: &TestStrStructIntPtrSliDef{
					Field: []*int{
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructIntPtrSliDef{
				Field: []*int{
					&resInt3,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]int field.",
			args: args{
				v: &TestStrStructIntSliPtr{
					Field: &[]int{
						30,
						45,
						60,
					},
				},
				idx: 0,
			},
			want: &TestStrStructIntSliPtr{
				Field: &[]int{
					40,
					45,
					50,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to an empty *[]int field.",
			args: args{
				v:   &TestStrStructIntSliPtr{},
				idx: 0,
			},
			want:    &TestStrStructIntSliPtr{},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]*int field.",
			args: args{
				v: &TestStrStructIntPtrSliPtr{
					Field: &[]*int{
						&argInt4,
						&argInt5,
						&argInt6,
					},
				},
				idx: 0,
			},
			want: &TestStrStructIntPtrSliPtr{
				Field: &[]*int{
					&resInt4,
					&resInt5,
					&resInt6,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]*int field.",
			args: args{
				v: &TestStrStructIntPtrSliPtr{
					Field: &[]*int{
						nil,
						nil,
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructIntPtrSliPtr{
				Field: &[]*int{
					nil,
					nil,
					nil,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags (with default) to a non-empty *[]*int field.",
			args: args{
				v: &TestStrStructIntPtrSliPtrDef{
					Field: &[]*int{
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructIntPtrSliPtrDef{
				Field: &[]*int{
					&resInt7,
				},
			},
			wantErr: false,
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
