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
		Field int32 `san:"max=41,min=no"`
	}
	type TestInt32StructBadMaxTag struct {
		Field int32 `san:"max=no,min=42"`
	}
	type TestInt32StructDef struct {
		Field int32 `san:"def=43"`
	}
	type TestInt32StructPtr struct {
		Field *int32 `san:"max=42,min=41"`
	}
	type TestInt32StructPtrDef struct {
		Field *int32 `san:"max=42,min=41,def=41"`
	}
	type TestInt32StructPtrBadDefMax struct {
		Field *int32 `san:"max=42,def=43"`
	}
	type TestInt32StructPtrBadDefTag struct {
		Field *int32 `san:"max=42,def=no"`
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
					Field: 40.0,
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
			name: "Ignores a nil *int32 field that was nil on a struct without a def tag.",
			args: args{
				v: &TestInt32StructPtr{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestInt32StructPtr{
				Field: nil,
			},
			wantErr: false,
		},
		{
			name: "Caps an *int32 field on a struct with the san:max tag.",
			args: args{
				v: &TestInt32StructPtrDef{
					Field: &argInt0,
				},
				idx: 0,
			},
			want: &TestInt32StructPtrDef{
				Field: &resInt0,
			},
			wantErr: false,
		},
		{
			name: "Puts a default value for a *int32 field that was nil on a struct with the tag.",
			args: args{
				v: &TestInt32StructPtrDef{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestInt32StructPtrDef{
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

func Test_sanitizeInt32Field_Slice(t *testing.T) {
	s, _ := New()

	type TestStrStructInt32Sli struct {
		Field []int32 `san:"max=50,min=40"`
	}
	type TestStrStructInt32PtrSli struct {
		Field []*int32 `san:"max=50,min=40"`
	}
	type TestStrStructInt32PtrSliDef struct {
		Field []*int32 `san:"max=50,min=40,def=42"`
	}
	type TestStrStructInt32SliPtr struct {
		Field *[]int32 `san:"max=50,min=40"`
	}
	type TestStrStructInt32PtrSliPtr struct {
		Field *[]*int32 `san:"max=50,min=40"`
	}
	type TestStrStructInt32PtrSliPtrDef struct {
		Field *[]*int32 `san:"max=50,min=40,def=42"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argInt320 := int32(30)
	resInt320 := int32(40)
	argInt321 := int32(45)
	resInt321 := int32(45)
	argInt322 := int32(60)
	resInt322 := int32(50)
	resInt323 := int32(42)
	argInt324 := int32(30)
	resInt324 := int32(40)
	argInt325 := int32(45)
	resInt325 := int32(45)
	argInt326 := int32(60)
	resInt326 := int32(50)
	resInt327 := int32(42)

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
			name: "Applies tags to a non-empty []int32 field.",
			args: args{
				v: &TestStrStructInt32Sli{
					Field: []int32{
						30,
						45,
						60,
					},
				},
				idx: 0,
			},
			want: &TestStrStructInt32Sli{
				Field: []int32{
					40,
					45,
					50,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to an empty []int32 field.",
			args: args{
				v:   &TestStrStructInt32Sli{},
				idx: 0,
			},
			want:    &TestStrStructInt32Sli{},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty []*int32 field.",
			args: args{
				v: &TestStrStructInt32PtrSli{
					Field: []*int32{
						&argInt320,
						&argInt321,
						&argInt322,
					},
				},
				idx: 0,
			},
			want: &TestStrStructInt32PtrSli{
				Field: []*int32{
					&resInt320,
					&resInt321,
					&resInt322,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty []*int32 field.",
			args: args{
				v: &TestStrStructInt32PtrSli{
					Field: []*int32{
						nil,
						nil,
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructInt32PtrSli{
				Field: []*int32{
					nil,
					nil,
					nil,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags (with default) to a non-empty []*int32 field.",
			args: args{
				v: &TestStrStructInt32PtrSliDef{
					Field: []*int32{
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructInt32PtrSliDef{
				Field: []*int32{
					&resInt323,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]int32 field.",
			args: args{
				v: &TestStrStructInt32SliPtr{
					Field: &[]int32{
						30,
						45,
						60,
					},
				},
				idx: 0,
			},
			want: &TestStrStructInt32SliPtr{
				Field: &[]int32{
					40,
					45,
					50,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to an empty *[]int32 field.",
			args: args{
				v:   &TestStrStructInt32SliPtr{},
				idx: 0,
			},
			want:    &TestStrStructInt32SliPtr{},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]*int32 field.",
			args: args{
				v: &TestStrStructInt32PtrSliPtr{
					Field: &[]*int32{
						&argInt324,
						&argInt325,
						&argInt326,
					},
				},
				idx: 0,
			},
			want: &TestStrStructInt32PtrSliPtr{
				Field: &[]*int32{
					&resInt324,
					&resInt325,
					&resInt326,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]*int32 field.",
			args: args{
				v: &TestStrStructInt32PtrSliPtr{
					Field: &[]*int32{
						nil,
						nil,
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructInt32PtrSliPtr{
				Field: &[]*int32{
					nil,
					nil,
					nil,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags (with default) to a non-empty *[]*int32 field.",
			args: args{
				v: &TestStrStructInt32PtrSliPtrDef{
					Field: &[]*int32{
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructInt32PtrSliPtrDef{
				Field: &[]*int32{
					&resInt327,
				},
			},
			wantErr: false,
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
