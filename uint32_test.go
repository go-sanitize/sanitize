package sanitize

import (
	"reflect"
	"testing"
)

func Test_sanitizeUint32Field(t *testing.T) {
	s, _ := New()

	type TestUint32Struct struct {
		Field uint32 `san:"max=42,min=41"`
	}
	type TestUint32StructNegativeMinTag struct {
		Field uint32 `san:"max=41,min=-2"`
	}
	type TestUint32StructNegativeMaxTag struct {
		Field uint32 `san:"max=-2,min=42"`
	}
	type TestUint32StructBadMaxMin struct {
		Field uint32 `san:"max=41,min=42"`
	}
	type TestUint32StructBadMinTag struct {
		Field uint32 `san:"max=41,min=no"`
	}
	type TestUint32StructBadMaxTag struct {
		Field uint32 `san:"max=no,min=42"`
	}
	type TestUint32StructDef struct {
		Field uint32 `san:"def=43"`
	}
	type TestUint32StructPtr struct {
		Field *uint32 `san:"max=42,min=41"`
	}
	type TestUint32StructPtrDef struct {
		Field *uint32 `san:"max=42,min=41,def=41"`
	}
	type TestUint32StructPtrBadDefMax struct {
		Field *uint32 `san:"max=42,def=43"`
	}
	type TestUint32StructPtrBadDefTag struct {
		Field *uint32 `san:"max=42,def=no"`
	}
	type TestUint32StructPtrBadDefMin struct {
		Field *uint32 `san:"min=41,def=40"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argInt0 := uint32(43)
	resInt0 := uint32(42)
	resInt1 := uint32(41)

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
			name: "Caps an uint32 field on a struct with the san:max tag.",
			args: args{
				v: &TestUint32Struct{
					Field: 43,
				},
				idx: 0,
			},
			want: &TestUint32Struct{
				Field: 42,
			},
			wantErr: false,
		},
		{
			name: "Raises an uint32 field on a struct with the san:min tag.",
			args: args{
				v: &TestUint32Struct{
					Field: 40.0,
				},
				idx: 0,
			},
			want: &TestUint32Struct{
				Field: 41,
			},
			wantErr: false,
		},
		{
			name: "Returns an error if a san:min tag on a uint32 field is below 0.",
			args: args{
				v: &TestUint32StructNegativeMinTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint32StructNegativeMinTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a uint32 field is below 0.",
			args: args{
				v: &TestUint32StructNegativeMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint32StructNegativeMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:min tag on a uint32 field is not numeric.",
			args: args{
				v: &TestUint32StructBadMinTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint32StructBadMinTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a uint32 field is not numeric.",
			args: args{
				v: &TestUint32StructBadMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint32StructBadMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Default value does not affect an uint32 field on a struct with the tag.",
			args: args{
				v:   &TestUint32StructDef{},
				idx: 0,
			},
			want:    &TestUint32StructDef{},
			wantErr: false,
		},
		{
			name: "Returns an error if the maximum value is smaller than the minimum on a struct with the tags.",
			args: args{
				v: &TestUint32StructBadMaxMin{
					Field: 2,
				},
				idx: 0,
			},
			want: &TestUint32StructBadMaxMin{
				Field: 2,
			},
			wantErr: true,
		},
		{
			name: "Ignores a nil *uint32 field that was nil on a struct without a def tag.",
			args: args{
				v: &TestUint32StructPtr{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestUint32StructPtr{
				Field: nil,
			},
			wantErr: false,
		},
		{
			name: "Caps an *uint32 field on a struct with the san:max tag.",
			args: args{
				v: &TestUint32StructPtrDef{
					Field: &argInt0,
				},
				idx: 0,
			},
			want: &TestUint32StructPtrDef{
				Field: &resInt0,
			},
			wantErr: false,
		},
		{
			name: "Puts a default value for a *uint32 field that was nil on a struct with the tag.",
			args: args{
				v: &TestUint32StructPtrDef{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestUint32StructPtrDef{
				Field: &resInt1,
			},
			wantErr: false,
		},
		{
			name: "Returns an error when the def component for a *uint32 field is not numeric.",
			args: args{
				v: &TestUint32StructPtrBadDefTag{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestUint32StructPtrBadDefTag{
				Field: nil,
			},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the max component are both present, and the def is higher than the max for a *uint32 field that was nil on a struct with the tag.",
			args: args{
				v: &TestUint32StructPtrBadDefMax{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestUint32StructPtrBadDefMax{},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the low component are both present, and the def is lower than the min for a *uint32 field that was nil on a struct with the tag.",
			args: args{
				v: &TestUint32StructPtrBadDefMin{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestUint32StructPtrBadDefMin{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeUint32Field(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeUint32Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeUint32Field() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}

func Test_sanitizeUint32Field_Slice(t *testing.T) {
	s, _ := New()

	type TestStrStructUint32Sli struct {
		Field []uint32 `san:"max=50,min=40"`
	}
	type TestStrStructUint32PtrSli struct {
		Field []*uint32 `san:"max=50,min=40"`
	}
	type TestStrStructUint32PtrSliDef struct {
		Field []*uint32 `san:"max=50,min=40,def=42"`
	}
	type TestStrStructUint32SliPtr struct {
		Field *[]uint32 `san:"max=50,min=40"`
	}
	type TestStrStructUint32PtrSliPtr struct {
		Field *[]*uint32 `san:"max=50,min=40"`
	}
	type TestStrStructUint32PtrSliPtrDef struct {
		Field *[]*uint32 `san:"max=50,min=40,def=42"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argUint320 := uint32(30)
	resUint320 := uint32(40)
	argUint321 := uint32(45)
	resUint321 := uint32(45)
	argUint322 := uint32(60)
	resUint322 := uint32(50)
	resUint323 := uint32(42)
	argUint324 := uint32(30)
	resUint324 := uint32(40)
	argUint325 := uint32(45)
	resUint325 := uint32(45)
	argUint326 := uint32(60)
	resUint326 := uint32(50)
	resUint327 := uint32(42)

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
			name: "Applies tags to a non-empty []uint32 field.",
			args: args{
				v: &TestStrStructUint32Sli{
					Field: []uint32{
						30,
						45,
						60,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint32Sli{
				Field: []uint32{
					40,
					45,
					50,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to an empty []uint32 field.",
			args: args{
				v:   &TestStrStructUint32Sli{},
				idx: 0,
			},
			want:    &TestStrStructUint32Sli{},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty []*uint32 field.",
			args: args{
				v: &TestStrStructUint32PtrSli{
					Field: []*uint32{
						&argUint320,
						&argUint321,
						&argUint322,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint32PtrSli{
				Field: []*uint32{
					&resUint320,
					&resUint321,
					&resUint322,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty []*uint32 field.",
			args: args{
				v: &TestStrStructUint32PtrSli{
					Field: []*uint32{
						nil,
						nil,
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint32PtrSli{
				Field: []*uint32{
					nil,
					nil,
					nil,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags (with default) to a non-empty []*uint32 field.",
			args: args{
				v: &TestStrStructUint32PtrSliDef{
					Field: []*uint32{
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint32PtrSliDef{
				Field: []*uint32{
					&resUint323,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]uint32 field.",
			args: args{
				v: &TestStrStructUint32SliPtr{
					Field: &[]uint32{
						30,
						45,
						60,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint32SliPtr{
				Field: &[]uint32{
					40,
					45,
					50,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to an empty *[]uint32 field.",
			args: args{
				v:   &TestStrStructUint32SliPtr{},
				idx: 0,
			},
			want:    &TestStrStructUint32SliPtr{},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]*uint32 field.",
			args: args{
				v: &TestStrStructUint32PtrSliPtr{
					Field: &[]*uint32{
						&argUint324,
						&argUint325,
						&argUint326,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint32PtrSliPtr{
				Field: &[]*uint32{
					&resUint324,
					&resUint325,
					&resUint326,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]*uint32 field.",
			args: args{
				v: &TestStrStructUint32PtrSliPtr{
					Field: &[]*uint32{
						nil,
						nil,
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint32PtrSliPtr{
				Field: &[]*uint32{
					nil,
					nil,
					nil,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags (with default) to a non-empty *[]*uint32 field.",
			args: args{
				v: &TestStrStructUint32PtrSliPtrDef{
					Field: &[]*uint32{
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint32PtrSliPtrDef{
				Field: &[]*uint32{
					&resUint327,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeUint32Field(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeUint32Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeUint32Field() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}
