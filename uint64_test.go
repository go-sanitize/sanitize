package sanitize

import (
	"reflect"
	"testing"
)

func Test_sanitizeUint64Field(t *testing.T) {
	s, _ := New()

	type TestUint64Struct struct {
		Field uint64 `san:"max=42,min=41"`
	}
	type TestUint64StructNegativeMinTag struct {
		Field uint64 `san:"max=41,min=-2"`
	}
	type TestUint64StructNegativeMaxTag struct {
		Field uint64 `san:"max=-2,min=42"`
	}
	type TestUint64StructBadMaxMin struct {
		Field uint64 `san:"max=41,min=42"`
	}
	type TestUint64StructBadMinTag struct {
		Field uint64 `san:"max=41,min=no"`
	}
	type TestUint64StructBadMaxTag struct {
		Field uint64 `san:"max=no,min=42"`
	}
	type TestUint64StructDef struct {
		Field uint64 `san:"def=43"`
	}
	type TestUint64StructPtr struct {
		Field *uint64 `san:"max=42,min=41"`
	}
	type TestUint64StructPtrDef struct {
		Field *uint64 `san:"max=42,min=41,def=41"`
	}
	type TestUint64StructPtrBadDefMax struct {
		Field *uint64 `san:"max=42,def=43"`
	}
	type TestUint64StructPtrBadDefTag struct {
		Field *uint64 `san:"max=42,def=no"`
	}
	type TestUint64StructPtrBadDefMin struct {
		Field *uint64 `san:"min=41,def=40"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argInt0 := uint64(43)
	resInt0 := uint64(42)
	resInt1 := uint64(41)

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
			name: "Caps an uint64 field on a struct with the san:max tag.",
			args: args{
				v: &TestUint64Struct{
					Field: 43,
				},
				idx: 0,
			},
			want: &TestUint64Struct{
				Field: 42,
			},
			wantErr: false,
		},
		{
			name: "Raises an uint64 field on a struct with the san:min tag.",
			args: args{
				v: &TestUint64Struct{
					Field: 40.0,
				},
				idx: 0,
			},
			want: &TestUint64Struct{
				Field: 41,
			},
			wantErr: false,
		},
		{
			name: "Returns an error if a san:min tag on a uint64 field is below 0.",
			args: args{
				v: &TestUint64StructNegativeMinTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint64StructNegativeMinTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a uint64 field is below 0.",
			args: args{
				v: &TestUint64StructNegativeMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint64StructNegativeMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:min tag on a uint64 field is not numeric.",
			args: args{
				v: &TestUint64StructBadMinTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint64StructBadMinTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a uint64 field is not numeric.",
			args: args{
				v: &TestUint64StructBadMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint64StructBadMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Default value does not affect an uint64 field on a struct with the tag.",
			args: args{
				v:   &TestUint64StructDef{},
				idx: 0,
			},
			want:    &TestUint64StructDef{},
			wantErr: false,
		},
		{
			name: "Returns an error if the maximum value is smaller than the minimum on a struct with the tags.",
			args: args{
				v: &TestUint64StructBadMaxMin{
					Field: 2,
				},
				idx: 0,
			},
			want: &TestUint64StructBadMaxMin{
				Field: 2,
			},
			wantErr: true,
		},
		{
			name: "Ignores a nil *uint64 field that was nil on a struct without a def tag.",
			args: args{
				v: &TestUint64StructPtr{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestUint64StructPtr{
				Field: nil,
			},
			wantErr: false,
		},
		{
			name: "Caps an *uint64 field on a struct with the san:max tag.",
			args: args{
				v: &TestUint64StructPtrDef{
					Field: &argInt0,
				},
				idx: 0,
			},
			want: &TestUint64StructPtrDef{
				Field: &resInt0,
			},
			wantErr: false,
		},
		{
			name: "Puts a default value for a *uint64 field that was nil on a struct with the tag.",
			args: args{
				v: &TestUint64StructPtrDef{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestUint64StructPtrDef{
				Field: &resInt1,
			},
			wantErr: false,
		},
		{
			name: "Returns an error when the def component for a *uint64 field is not numeric.",
			args: args{
				v: &TestUint64StructPtrBadDefTag{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestUint64StructPtrBadDefTag{
				Field: nil,
			},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the max component are both present, and the def is higher than the max for a *uint64 field that was nil on a struct with the tag.",
			args: args{
				v: &TestUint64StructPtrBadDefMax{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestUint64StructPtrBadDefMax{},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the low component are both present, and the def is lower than the min for a *uint64 field that was nil on a struct with the tag.",
			args: args{
				v: &TestUint64StructPtrBadDefMin{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestUint64StructPtrBadDefMin{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeUint64Field(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeUint64Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeUint64Field() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}

func Test_sanitizeUint64Field_Slice(t *testing.T) {
	s, _ := New()

	type TestStrStructUint64Sli struct {
		Field []uint64 `san:"max=50,min=40"`
	}
	type TestStrStructUint64PtrSli struct {
		Field []*uint64 `san:"max=50,min=40"`
	}
	type TestStrStructUint64PtrSliDef struct {
		Field []*uint64 `san:"max=50,min=40,def=42"`
	}
	type TestStrStructUint64SliPtr struct {
		Field *[]uint64 `san:"max=50,min=40"`
	}
	type TestStrStructUint64PtrSliPtr struct {
		Field *[]*uint64 `san:"max=50,min=40"`
	}
	type TestStrStructUint64PtrSliPtrDef struct {
		Field *[]*uint64 `san:"max=50,min=40,def=42"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argUint640 := uint64(30)
	resUint640 := uint64(40)
	argUint641 := uint64(45)
	resUint641 := uint64(45)
	argUint642 := uint64(60)
	resUint642 := uint64(50)
	resUint643 := uint64(42)
	argUint644 := uint64(30)
	resUint644 := uint64(40)
	argUint645 := uint64(45)
	resUint645 := uint64(45)
	argUint646 := uint64(60)
	resUint646 := uint64(50)
	resUint647 := uint64(42)

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
			name: "Applies tags to a non-empty []uint64 field.",
			args: args{
				v: &TestStrStructUint64Sli{
					Field: []uint64{
						30,
						45,
						60,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint64Sli{
				Field: []uint64{
					40,
					45,
					50,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to an empty []uint64 field.",
			args: args{
				v:   &TestStrStructUint64Sli{},
				idx: 0,
			},
			want:    &TestStrStructUint64Sli{},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty []*uint64 field.",
			args: args{
				v: &TestStrStructUint64PtrSli{
					Field: []*uint64{
						&argUint640,
						&argUint641,
						&argUint642,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint64PtrSli{
				Field: []*uint64{
					&resUint640,
					&resUint641,
					&resUint642,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty []*uint64 field.",
			args: args{
				v: &TestStrStructUint64PtrSli{
					Field: []*uint64{
						nil,
						nil,
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint64PtrSli{
				Field: []*uint64{
					nil,
					nil,
					nil,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags (with default) to a non-empty []*uint64 field.",
			args: args{
				v: &TestStrStructUint64PtrSliDef{
					Field: []*uint64{
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint64PtrSliDef{
				Field: []*uint64{
					&resUint643,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]uint64 field.",
			args: args{
				v: &TestStrStructUint64SliPtr{
					Field: &[]uint64{
						30,
						45,
						60,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint64SliPtr{
				Field: &[]uint64{
					40,
					45,
					50,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to an empty *[]uint64 field.",
			args: args{
				v:   &TestStrStructUint64SliPtr{},
				idx: 0,
			},
			want:    &TestStrStructUint64SliPtr{},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]*uint64 field.",
			args: args{
				v: &TestStrStructUint64PtrSliPtr{
					Field: &[]*uint64{
						&argUint644,
						&argUint645,
						&argUint646,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint64PtrSliPtr{
				Field: &[]*uint64{
					&resUint644,
					&resUint645,
					&resUint646,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]*uint64 field.",
			args: args{
				v: &TestStrStructUint64PtrSliPtr{
					Field: &[]*uint64{
						nil,
						nil,
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint64PtrSliPtr{
				Field: &[]*uint64{
					nil,
					nil,
					nil,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags (with default) to a non-empty *[]*uint64 field.",
			args: args{
				v: &TestStrStructUint64PtrSliPtrDef{
					Field: &[]*uint64{
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint64PtrSliPtrDef{
				Field: &[]*uint64{
					&resUint647,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeUint64Field(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeUint64Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeUint64Field() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}
