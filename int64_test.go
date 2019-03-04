package sanitize

import (
	"reflect"
	"testing"
)

func Test_sanitizeInt64Field(t *testing.T) {
	s, _ := New()

	type TestInt64Struct struct {
		Field int64 `san:"max=42,min=41"`
	}
	type TestInt64StructNegativeMinTag struct {
		Field int64 `san:"max=41,min=-2"`
	}
	type TestInt64StructNegativeMaxTag struct {
		Field int64 `san:"max=-2,min=42"`
	}
	type TestInt64StructBadMaxMin struct {
		Field int64 `san:"max=41,min=42"`
	}
	type TestInt64StructBadMinTag struct {
		Field int64 `san:"max=41,min=no"`
	}
	type TestInt64StructBadMaxTag struct {
		Field int64 `san:"max=no,min=42"`
	}
	type TestInt64StructDef struct {
		Field int64 `san:"def=43"`
	}
	type TestInt64StructPtr struct {
		Field *int64 `san:"max=42,min=41"`
	}
	type TestInt64StructPtrDef struct {
		Field *int64 `san:"max=42,min=41,def=41"`
	}
	type TestInt64StructPtrBadDefMax struct {
		Field *int64 `san:"max=42,def=43"`
	}
	type TestInt64StructPtrBadDefTag struct {
		Field *int64 `san:"max=42,def=no"`
	}
	type TestInt64StructPtrBadDefMin struct {
		Field *int64 `san:"min=41,def=40"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argInt0 := int64(43)
	resInt0 := int64(42)
	resInt1 := int64(41)

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
			name: "Caps an int64 field on a struct with the san:max tag.",
			args: args{
				v: &TestInt64Struct{
					Field: 43,
				},
				idx: 0,
			},
			want: &TestInt64Struct{
				Field: 42,
			},
			wantErr: false,
		},
		{
			name: "Raises an int64 field on a struct with the san:min tag.",
			args: args{
				v: &TestInt64Struct{
					Field: 40.0,
				},
				idx: 0,
			},
			want: &TestInt64Struct{
				Field: 41,
			},
			wantErr: false,
		},
		{
			name: "Returns an error if a san:min tag on a int64 field is below 0.",
			args: args{
				v: &TestInt64StructNegativeMinTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestInt64StructNegativeMinTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a int64 field is below 0.",
			args: args{
				v: &TestInt64StructNegativeMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestInt64StructNegativeMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:min tag on a int64 field is not numeric.",
			args: args{
				v: &TestInt64StructBadMinTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestInt64StructBadMinTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a int64 field is not numeric.",
			args: args{
				v: &TestInt64StructBadMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestInt64StructBadMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Default value does not affect an int64 field on a struct with the tag.",
			args: args{
				v:   &TestInt64StructDef{},
				idx: 0,
			},
			want:    &TestInt64StructDef{},
			wantErr: false,
		},
		{
			name: "Returns an error if the maximum value is smaller than the minimum on a struct with the tags.",
			args: args{
				v: &TestInt64StructBadMaxMin{
					Field: 2,
				},
				idx: 0,
			},
			want: &TestInt64StructBadMaxMin{
				Field: 2,
			},
			wantErr: true,
		},
		{
			name: "Ignores a nil *int64 field that was nil on a struct without a def tag.",
			args: args{
				v: &TestInt64StructPtr{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestInt64StructPtr{
				Field: nil,
			},
			wantErr: false,
		},
		{
			name: "Caps an *int64 field on a struct with the san:max tag.",
			args: args{
				v: &TestInt64StructPtrDef{
					Field: &argInt0,
				},
				idx: 0,
			},
			want: &TestInt64StructPtrDef{
				Field: &resInt0,
			},
			wantErr: false,
		},
		{
			name: "Puts a default value for a *int64 field that was nil on a struct with the tag.",
			args: args{
				v: &TestInt64StructPtrDef{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestInt64StructPtrDef{
				Field: &resInt1,
			},
			wantErr: false,
		},
		{
			name: "Returns an error when the def component for a *int64 field is not numeric.",
			args: args{
				v: &TestInt64StructPtrBadDefTag{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestInt64StructPtrBadDefTag{
				Field: nil,
			},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the max component are both present, and the def is higher than the max for a *int64 field that was nil on a struct with the tag.",
			args: args{
				v: &TestInt64StructPtrBadDefMax{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestInt64StructPtrBadDefMax{},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the low component are both present, and the def is lower than the min for a *int64 field that was nil on a struct with the tag.",
			args: args{
				v: &TestInt64StructPtrBadDefMin{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestInt64StructPtrBadDefMin{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeInt64Field(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeInt64Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeInt64Field() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}

func Test_sanitizeInt64Field_Slice(t *testing.T) {
	s, _ := New()

	type TestStrStructInt64Sli struct {
		Field []int64 `san:"max=50,min=40"`
	}
	type TestStrStructInt64PtrSli struct {
		Field []*int64 `san:"max=50,min=40"`
	}
	type TestStrStructInt64PtrSliDef struct {
		Field []*int64 `san:"max=50,min=40,def=42"`
	}
	type TestStrStructInt64SliPtr struct {
		Field *[]int64 `san:"max=50,min=40"`
	}
	type TestStrStructInt64PtrSliPtr struct {
		Field *[]*int64 `san:"max=50,min=40"`
	}
	type TestStrStructInt64PtrSliPtrDef struct {
		Field *[]*int64 `san:"max=50,min=40,def=42"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argInt640 := int64(30)
	resInt640 := int64(40)
	argInt641 := int64(45)
	resInt641 := int64(45)
	argInt642 := int64(60)
	resInt642 := int64(50)
	resInt643 := int64(42)
	argInt644 := int64(30)
	resInt644 := int64(40)
	argInt645 := int64(45)
	resInt645 := int64(45)
	argInt646 := int64(60)
	resInt646 := int64(50)
	resInt647 := int64(42)

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
			name: "Applies tags to a non-empty []int64 field.",
			args: args{
				v: &TestStrStructInt64Sli{
					Field: []int64{
						30,
						45,
						60,
					},
				},
				idx: 0,
			},
			want: &TestStrStructInt64Sli{
				Field: []int64{
					40,
					45,
					50,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to an empty []int64 field.",
			args: args{
				v:   &TestStrStructInt64Sli{},
				idx: 0,
			},
			want:    &TestStrStructInt64Sli{},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty []*int64 field.",
			args: args{
				v: &TestStrStructInt64PtrSli{
					Field: []*int64{
						&argInt640,
						&argInt641,
						&argInt642,
					},
				},
				idx: 0,
			},
			want: &TestStrStructInt64PtrSli{
				Field: []*int64{
					&resInt640,
					&resInt641,
					&resInt642,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty []*int64 field.",
			args: args{
				v: &TestStrStructInt64PtrSli{
					Field: []*int64{
						nil,
						nil,
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructInt64PtrSli{
				Field: []*int64{
					nil,
					nil,
					nil,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags (with default) to a non-empty []*int64 field.",
			args: args{
				v: &TestStrStructInt64PtrSliDef{
					Field: []*int64{
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructInt64PtrSliDef{
				Field: []*int64{
					&resInt643,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]int64 field.",
			args: args{
				v: &TestStrStructInt64SliPtr{
					Field: &[]int64{
						30,
						45,
						60,
					},
				},
				idx: 0,
			},
			want: &TestStrStructInt64SliPtr{
				Field: &[]int64{
					40,
					45,
					50,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to an empty *[]int64 field.",
			args: args{
				v:   &TestStrStructInt64SliPtr{},
				idx: 0,
			},
			want:    &TestStrStructInt64SliPtr{},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]*int64 field.",
			args: args{
				v: &TestStrStructInt64PtrSliPtr{
					Field: &[]*int64{
						&argInt644,
						&argInt645,
						&argInt646,
					},
				},
				idx: 0,
			},
			want: &TestStrStructInt64PtrSliPtr{
				Field: &[]*int64{
					&resInt644,
					&resInt645,
					&resInt646,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]*int64 field.",
			args: args{
				v: &TestStrStructInt64PtrSliPtr{
					Field: &[]*int64{
						nil,
						nil,
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructInt64PtrSliPtr{
				Field: &[]*int64{
					nil,
					nil,
					nil,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags (with default) to a non-empty *[]*int64 field.",
			args: args{
				v: &TestStrStructInt64PtrSliPtrDef{
					Field: &[]*int64{
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructInt64PtrSliPtrDef{
				Field: &[]*int64{
					&resInt647,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeInt64Field(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeInt64Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeInt64Field() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}
