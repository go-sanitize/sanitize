package sanitize

import (
	"reflect"
	"testing"
)

func Test_sanitizeInt16Field(t *testing.T) {
	s, _ := New()

	type TestInt16Struct struct {
		Field int16 `san:"max=42,min=41"`
	}
	type TestInt16StructNegativeMinTag struct {
		Field int16 `san:"max=41,min=-2"`
	}
	type TestInt16StructNegativeMaxTag struct {
		Field int16 `san:"max=-2,min=42"`
	}
	type TestInt16StructBadMaxMin struct {
		Field int16 `san:"max=41,min=42"`
	}
	type TestInt16StructBadMinTag struct {
		Field int16 `san:"max=41,min=no"`
	}
	type TestInt16StructBadMaxTag struct {
		Field int16 `san:"max=no,min=42"`
	}
	type TestInt16StructDef struct {
		Field int16 `san:"def=43"`
	}
	type TestInt16StructPtr struct {
		Field *int16 `san:"max=42,min=41"`
	}
	type TestInt16StructPtrDef struct {
		Field *int16 `san:"max=42,min=41,def=41"`
	}
	type TestInt16StructPtrBadDefMax struct {
		Field *int16 `san:"max=42,def=43"`
	}
	type TestInt16StructPtrBadDefTag struct {
		Field *int16 `san:"max=42,def=no"`
	}
	type TestInt16StructPtrBadDefMin struct {
		Field *int16 `san:"min=41,def=40"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argInt0 := int16(43)
	resInt0 := int16(42)
	resInt1 := int16(41)

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
			name: "Caps an int16 field on a struct with the san:max tag.",
			args: args{
				v: &TestInt16Struct{
					Field: 43,
				},
				idx: 0,
			},
			want: &TestInt16Struct{
				Field: 42,
			},
			wantErr: false,
		},
		{
			name: "Raises an int16 field on a struct with the san:min tag.",
			args: args{
				v: &TestInt16Struct{
					Field: 40.0,
				},
				idx: 0,
			},
			want: &TestInt16Struct{
				Field: 41,
			},
			wantErr: false,
		},
		{
			name: "Returns an error if a san:min tag on a int16 field is below 0.",
			args: args{
				v: &TestInt16StructNegativeMinTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestInt16StructNegativeMinTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a int16 field is below 0.",
			args: args{
				v: &TestInt16StructNegativeMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestInt16StructNegativeMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:min tag on a int16 field is not numeric.",
			args: args{
				v: &TestInt16StructBadMinTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestInt16StructBadMinTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a int16 field is not numeric.",
			args: args{
				v: &TestInt16StructBadMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestInt16StructBadMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Default value does not affect an int16 field on a struct with the tag.",
			args: args{
				v:   &TestInt16StructDef{},
				idx: 0,
			},
			want:    &TestInt16StructDef{},
			wantErr: false,
		},
		{
			name: "Returns an error if the maximum value is smaller than the minimum on a struct with the tags.",
			args: args{
				v: &TestInt16StructBadMaxMin{
					Field: 2,
				},
				idx: 0,
			},
			want: &TestInt16StructBadMaxMin{
				Field: 2,
			},
			wantErr: true,
		},
		{
			name: "Ignores a nil *int16 field that was nil on a struct without a def tag.",
			args: args{
				v: &TestInt16StructPtr{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestInt16StructPtr{
				Field: nil,
			},
			wantErr: false,
		},
		{
			name: "Caps an *int16 field on a struct with the san:max tag.",
			args: args{
				v: &TestInt16StructPtrDef{
					Field: &argInt0,
				},
				idx: 0,
			},
			want: &TestInt16StructPtrDef{
				Field: &resInt0,
			},
			wantErr: false,
		},
		{
			name: "Puts a default value for a *int16 field that was nil on a struct with the tag.",
			args: args{
				v: &TestInt16StructPtrDef{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestInt16StructPtrDef{
				Field: &resInt1,
			},
			wantErr: false,
		},
		{
			name: "Returns an error when the def component for a *int16 field is not numeric.",
			args: args{
				v: &TestInt16StructPtrBadDefTag{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestInt16StructPtrBadDefTag{
				Field: nil,
			},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the max component are both present, and the def is higher than the max for a *int16 field that was nil on a struct with the tag.",
			args: args{
				v: &TestInt16StructPtrBadDefMax{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestInt16StructPtrBadDefMax{},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the low component are both present, and the def is lower than the min for a *int16 field that was nil on a struct with the tag.",
			args: args{
				v: &TestInt16StructPtrBadDefMin{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestInt16StructPtrBadDefMin{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeInt16Field(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeInt16Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeInt16Field() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}

func Test_sanitizeInt16Field_Slice(t *testing.T) {
	s, _ := New()

	type TestStrStructInt16Sli struct {
		Field []int16 `san:"max=50,min=40"`
	}
	type TestStrStructInt16PtrSli struct {
		Field []*int16 `san:"max=50,min=40"`
	}
	type TestStrStructInt16PtrSliDef struct {
		Field []*int16 `san:"max=50,min=40,def=42"`
	}
	type TestStrStructInt16SliPtr struct {
		Field *[]int16 `san:"max=50,min=40"`
	}
	type TestStrStructInt16PtrSliPtr struct {
		Field *[]*int16 `san:"max=50,min=40"`
	}
	type TestStrStructInt16PtrSliPtrDef struct {
		Field *[]*int16 `san:"max=50,min=40,def=42"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argInt160 := int16(30)
	resInt160 := int16(40)
	argInt161 := int16(45)
	resInt161 := int16(45)
	argInt162 := int16(60)
	resInt162 := int16(50)
	resInt163 := int16(42)
	argInt164 := int16(30)
	resInt164 := int16(40)
	argInt165 := int16(45)
	resInt165 := int16(45)
	argInt166 := int16(60)
	resInt166 := int16(50)
	resInt167 := int16(42)

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
			name: "Applies tags to a non-empty []int16 field.",
			args: args{
				v: &TestStrStructInt16Sli{
					Field: []int16{
						30,
						45,
						60,
					},
				},
				idx: 0,
			},
			want: &TestStrStructInt16Sli{
				Field: []int16{
					40,
					45,
					50,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to an empty []int16 field.",
			args: args{
				v:   &TestStrStructInt16Sli{},
				idx: 0,
			},
			want:    &TestStrStructInt16Sli{},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty []*int16 field.",
			args: args{
				v: &TestStrStructInt16PtrSli{
					Field: []*int16{
						&argInt160,
						&argInt161,
						&argInt162,
					},
				},
				idx: 0,
			},
			want: &TestStrStructInt16PtrSli{
				Field: []*int16{
					&resInt160,
					&resInt161,
					&resInt162,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty []*int16 field.",
			args: args{
				v: &TestStrStructInt16PtrSli{
					Field: []*int16{
						nil,
						nil,
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructInt16PtrSli{
				Field: []*int16{
					nil,
					nil,
					nil,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags (with default) to a non-empty []*int16 field.",
			args: args{
				v: &TestStrStructInt16PtrSliDef{
					Field: []*int16{
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructInt16PtrSliDef{
				Field: []*int16{
					&resInt163,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]int16 field.",
			args: args{
				v: &TestStrStructInt16SliPtr{
					Field: &[]int16{
						30,
						45,
						60,
					},
				},
				idx: 0,
			},
			want: &TestStrStructInt16SliPtr{
				Field: &[]int16{
					40,
					45,
					50,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to an empty *[]int16 field.",
			args: args{
				v:   &TestStrStructInt16SliPtr{},
				idx: 0,
			},
			want:    &TestStrStructInt16SliPtr{},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]*int16 field.",
			args: args{
				v: &TestStrStructInt16PtrSliPtr{
					Field: &[]*int16{
						&argInt164,
						&argInt165,
						&argInt166,
					},
				},
				idx: 0,
			},
			want: &TestStrStructInt16PtrSliPtr{
				Field: &[]*int16{
					&resInt164,
					&resInt165,
					&resInt166,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]*int16 field.",
			args: args{
				v: &TestStrStructInt16PtrSliPtr{
					Field: &[]*int16{
						nil,
						nil,
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructInt16PtrSliPtr{
				Field: &[]*int16{
					nil,
					nil,
					nil,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags (with default) to a non-empty *[]*int16 field.",
			args: args{
				v: &TestStrStructInt16PtrSliPtrDef{
					Field: &[]*int16{
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructInt16PtrSliPtrDef{
				Field: &[]*int16{
					&resInt167,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeInt16Field(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeInt16Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeInt16Field() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}
