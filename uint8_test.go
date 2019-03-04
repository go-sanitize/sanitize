package sanitize

import (
	"reflect"
	"testing"
)

func Test_sanitizeUint8Field(t *testing.T) {
	s, _ := New()

	type TestUint8Struct struct {
		Field uint8 `san:"max=42,min=41"`
	}
	type TestUint8StructNegativeMinTag struct {
		Field uint8 `san:"max=41,min=-2"`
	}
	type TestUint8StructNegativeMaxTag struct {
		Field uint8 `san:"max=-2,min=42"`
	}
	type TestUint8StructBadMaxMin struct {
		Field uint8 `san:"max=41,min=42"`
	}
	type TestUint8StructBadMinTag struct {
		Field uint8 `san:"max=41,min=no"`
	}
	type TestUint8StructBadMaxTag struct {
		Field uint8 `san:"max=no,min=42"`
	}
	type TestUint8StructDef struct {
		Field uint8 `san:"def=43"`
	}
	type TestUint8StructPtr struct {
		Field *uint8 `san:"max=42,min=41"`
	}
	type TestUint8StructPtrDef struct {
		Field *uint8 `san:"max=42,min=41,def=41"`
	}
	type TestUint8StructPtrBadDefMax struct {
		Field *uint8 `san:"max=42,def=43"`
	}
	type TestUint8StructPtrBadDefTag struct {
		Field *uint8 `san:"max=42,def=no"`
	}
	type TestUint8StructPtrBadDefMin struct {
		Field *uint8 `san:"min=41,def=40"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argInt0 := uint8(43)
	resInt0 := uint8(42)
	resInt1 := uint8(41)

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
			name: "Caps an uint8 field on a struct with the san:max tag.",
			args: args{
				v: &TestUint8Struct{
					Field: 43,
				},
				idx: 0,
			},
			want: &TestUint8Struct{
				Field: 42,
			},
			wantErr: false,
		},
		{
			name: "Raises an uint8 field on a struct with the san:min tag.",
			args: args{
				v: &TestUint8Struct{
					Field: 40.0,
				},
				idx: 0,
			},
			want: &TestUint8Struct{
				Field: 41,
			},
			wantErr: false,
		},
		{
			name: "Returns an error if a san:min tag on a uint8 field is below 0.",
			args: args{
				v: &TestUint8StructNegativeMinTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint8StructNegativeMinTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a uint8 field is below 0.",
			args: args{
				v: &TestUint8StructNegativeMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint8StructNegativeMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:min tag on a uint8 field is not numeric.",
			args: args{
				v: &TestUint8StructBadMinTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint8StructBadMinTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a uint8 field is not numeric.",
			args: args{
				v: &TestUint8StructBadMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint8StructBadMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Default value does not affect an uint8 field on a struct with the tag.",
			args: args{
				v:   &TestUint8StructDef{},
				idx: 0,
			},
			want:    &TestUint8StructDef{},
			wantErr: false,
		},
		{
			name: "Returns an error if the maximum value is smaller than the minimum on a struct with the tags.",
			args: args{
				v: &TestUint8StructBadMaxMin{
					Field: 2,
				},
				idx: 0,
			},
			want: &TestUint8StructBadMaxMin{
				Field: 2,
			},
			wantErr: true,
		},
		{
			name: "Ignores a nil *uint8 field that was nil on a struct without a def tag.",
			args: args{
				v: &TestUint8StructPtr{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestUint8StructPtr{
				Field: nil,
			},
			wantErr: false,
		},
		{
			name: "Caps an *uint8 field on a struct with the san:max tag.",
			args: args{
				v: &TestUint8StructPtrDef{
					Field: &argInt0,
				},
				idx: 0,
			},
			want: &TestUint8StructPtrDef{
				Field: &resInt0,
			},
			wantErr: false,
		},
		{
			name: "Puts a default value for a *uint8 field that was nil on a struct with the tag.",
			args: args{
				v: &TestUint8StructPtrDef{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestUint8StructPtrDef{
				Field: &resInt1,
			},
			wantErr: false,
		},
		{
			name: "Returns an error when the def component for a *uint8 field is not numeric.",
			args: args{
				v: &TestUint8StructPtrBadDefTag{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestUint8StructPtrBadDefTag{
				Field: nil,
			},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the max component are both present, and the def is higher than the max for a *uint8 field that was nil on a struct with the tag.",
			args: args{
				v: &TestUint8StructPtrBadDefMax{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestUint8StructPtrBadDefMax{},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the low component are both present, and the def is lower than the min for a *uint8 field that was nil on a struct with the tag.",
			args: args{
				v: &TestUint8StructPtrBadDefMin{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestUint8StructPtrBadDefMin{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeUint8Field(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeUint8Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeUint8Field() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}

func Test_sanitizeUint8Field_Slice(t *testing.T) {
	s, _ := New()

	type TestStrStructUint8Sli struct {
		Field []uint8 `san:"max=50,min=40"`
	}
	type TestStrStructUint8PtrSli struct {
		Field []*uint8 `san:"max=50,min=40"`
	}
	type TestStrStructUint8PtrSliDef struct {
		Field []*uint8 `san:"max=50,min=40,def=42"`
	}
	type TestStrStructUint8SliPtr struct {
		Field *[]uint8 `san:"max=50,min=40"`
	}
	type TestStrStructUint8PtrSliPtr struct {
		Field *[]*uint8 `san:"max=50,min=40"`
	}
	type TestStrStructUint8PtrSliPtrDef struct {
		Field *[]*uint8 `san:"max=50,min=40,def=42"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argUint80 := uint8(30)
	resUint80 := uint8(40)
	argUint81 := uint8(45)
	resUint81 := uint8(45)
	argUint82 := uint8(60)
	resUint82 := uint8(50)
	resUint83 := uint8(42)
	argUint84 := uint8(30)
	resUint84 := uint8(40)
	argUint85 := uint8(45)
	resUint85 := uint8(45)
	argUint86 := uint8(60)
	resUint86 := uint8(50)
	resUint87 := uint8(42)

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
			name: "Applies tags to a non-empty []uint8 field.",
			args: args{
				v: &TestStrStructUint8Sli{
					Field: []uint8{
						30,
						45,
						60,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint8Sli{
				Field: []uint8{
					40,
					45,
					50,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to an empty []uint8 field.",
			args: args{
				v:   &TestStrStructUint8Sli{},
				idx: 0,
			},
			want:    &TestStrStructUint8Sli{},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty []*uint8 field.",
			args: args{
				v: &TestStrStructUint8PtrSli{
					Field: []*uint8{
						&argUint80,
						&argUint81,
						&argUint82,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint8PtrSli{
				Field: []*uint8{
					&resUint80,
					&resUint81,
					&resUint82,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty []*uint8 field.",
			args: args{
				v: &TestStrStructUint8PtrSli{
					Field: []*uint8{
						nil,
						nil,
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint8PtrSli{
				Field: []*uint8{
					nil,
					nil,
					nil,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags (with default) to a non-empty []*uint8 field.",
			args: args{
				v: &TestStrStructUint8PtrSliDef{
					Field: []*uint8{
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint8PtrSliDef{
				Field: []*uint8{
					&resUint83,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]uint8 field.",
			args: args{
				v: &TestStrStructUint8SliPtr{
					Field: &[]uint8{
						30,
						45,
						60,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint8SliPtr{
				Field: &[]uint8{
					40,
					45,
					50,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to an empty *[]uint8 field.",
			args: args{
				v:   &TestStrStructUint8SliPtr{},
				idx: 0,
			},
			want:    &TestStrStructUint8SliPtr{},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]*uint8 field.",
			args: args{
				v: &TestStrStructUint8PtrSliPtr{
					Field: &[]*uint8{
						&argUint84,
						&argUint85,
						&argUint86,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint8PtrSliPtr{
				Field: &[]*uint8{
					&resUint84,
					&resUint85,
					&resUint86,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]*uint8 field.",
			args: args{
				v: &TestStrStructUint8PtrSliPtr{
					Field: &[]*uint8{
						nil,
						nil,
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint8PtrSliPtr{
				Field: &[]*uint8{
					nil,
					nil,
					nil,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags (with default) to a non-empty *[]*uint8 field.",
			args: args{
				v: &TestStrStructUint8PtrSliPtrDef{
					Field: &[]*uint8{
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint8PtrSliPtrDef{
				Field: &[]*uint8{
					&resUint87,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeUint8Field(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeUint8Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeUint8Field() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}
