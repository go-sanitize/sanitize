package sanitize

import (
	"reflect"
	"testing"
)

func Test_sanitizeUint16Field(t *testing.T) {
	s, _ := New()

	type TestUint16Struct struct {
		Field uint16 `san:"max=42,min=41"`
	}
	type TestUint16StructNegativeMinTag struct {
		Field uint16 `san:"max=41,min=-2"`
	}
	type TestUint16StructNegativeMaxTag struct {
		Field uint16 `san:"max=-2,min=42"`
	}
	type TestUint16StructBadMaxMin struct {
		Field uint16 `san:"max=41,min=42"`
	}
	type TestUint16StructBadMinTag struct {
		Field uint16 `san:"max=41,min=no"`
	}
	type TestUint16StructBadMaxTag struct {
		Field uint16 `san:"max=no,min=42"`
	}
	type TestUint16StructDef struct {
		Field uint16 `san:"def=43"`
	}
	type TestUint16StructPtr struct {
		Field *uint16 `san:"max=42,min=41"`
	}
	type TestUint16StructPtrDef struct {
		Field *uint16 `san:"max=42,min=41,def=41"`
	}
	type TestUint16StructPtrBadDefMax struct {
		Field *uint16 `san:"max=42,def=43"`
	}
	type TestUint16StructPtrBadDefTag struct {
		Field *uint16 `san:"max=42,def=no"`
	}
	type TestUint16StructPtrBadDefMin struct {
		Field *uint16 `san:"min=41,def=40"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argInt0 := uint16(43)
	resInt0 := uint16(42)
	resInt1 := uint16(41)

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
			name: "Caps an uint16 field on a struct with the san:max tag.",
			args: args{
				v: &TestUint16Struct{
					Field: 43,
				},
				idx: 0,
			},
			want: &TestUint16Struct{
				Field: 42,
			},
			wantErr: false,
		},
		{
			name: "Raises an uint16 field on a struct with the san:min tag.",
			args: args{
				v: &TestUint16Struct{
					Field: 40.0,
				},
				idx: 0,
			},
			want: &TestUint16Struct{
				Field: 41,
			},
			wantErr: false,
		},
		{
			name: "Returns an error if a san:min tag on a uint16 field is below 0.",
			args: args{
				v: &TestUint16StructNegativeMinTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint16StructNegativeMinTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a uint16 field is below 0.",
			args: args{
				v: &TestUint16StructNegativeMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint16StructNegativeMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:min tag on a uint16 field is not numeric.",
			args: args{
				v: &TestUint16StructBadMinTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint16StructBadMinTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a uint16 field is not numeric.",
			args: args{
				v: &TestUint16StructBadMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestUint16StructBadMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Default value does not affect an uint16 field on a struct with the tag.",
			args: args{
				v:   &TestUint16StructDef{},
				idx: 0,
			},
			want:    &TestUint16StructDef{},
			wantErr: false,
		},
		{
			name: "Returns an error if the maximum value is smaller than the minimum on a struct with the tags.",
			args: args{
				v: &TestUint16StructBadMaxMin{
					Field: 2,
				},
				idx: 0,
			},
			want: &TestUint16StructBadMaxMin{
				Field: 2,
			},
			wantErr: true,
		},
		{
			name: "Ignores a nil *uint16 field that was nil on a struct without a def tag.",
			args: args{
				v: &TestUint16StructPtr{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestUint16StructPtr{
				Field: nil,
			},
			wantErr: false,
		},
		{
			name: "Caps an *uint16 field on a struct with the san:max tag.",
			args: args{
				v: &TestUint16StructPtrDef{
					Field: &argInt0,
				},
				idx: 0,
			},
			want: &TestUint16StructPtrDef{
				Field: &resInt0,
			},
			wantErr: false,
		},
		{
			name: "Puts a default value for a *uint16 field that was nil on a struct with the tag.",
			args: args{
				v: &TestUint16StructPtrDef{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestUint16StructPtrDef{
				Field: &resInt1,
			},
			wantErr: false,
		},
		{
			name: "Returns an error when the def component for a *uint16 field is not numeric.",
			args: args{
				v: &TestUint16StructPtrBadDefTag{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestUint16StructPtrBadDefTag{
				Field: nil,
			},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the max component are both present, and the def is higher than the max for a *uint16 field that was nil on a struct with the tag.",
			args: args{
				v: &TestUint16StructPtrBadDefMax{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestUint16StructPtrBadDefMax{},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the low component are both present, and the def is lower than the min for a *uint16 field that was nil on a struct with the tag.",
			args: args{
				v: &TestUint16StructPtrBadDefMin{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestUint16StructPtrBadDefMin{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeUint16Field(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeUint16Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeUint16Field() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}

func Test_sanitizeUint16Field_Slice(t *testing.T) {
	s, _ := New()

	type TestStrStructUint16Sli struct {
		Field []uint16 `san:"max=50,min=40"`
	}
	type TestStrStructUint16PtrSli struct {
		Field []*uint16 `san:"max=50,min=40"`
	}
	type TestStrStructUint16PtrSliDef struct {
		Field []*uint16 `san:"max=50,min=40,def=42"`
	}
	type TestStrStructUint16SliPtr struct {
		Field *[]uint16 `san:"max=50,min=40"`
	}
	type TestStrStructUint16PtrSliPtr struct {
		Field *[]*uint16 `san:"max=50,min=40"`
	}
	type TestStrStructUint16PtrSliPtrDef struct {
		Field *[]*uint16 `san:"max=50,min=40,def=42"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argUint160 := uint16(30)
	resUint160 := uint16(40)
	argUint161 := uint16(45)
	resUint161 := uint16(45)
	argUint162 := uint16(60)
	resUint162 := uint16(50)
	resUint163 := uint16(42)
	argUint164 := uint16(30)
	resUint164 := uint16(40)
	argUint165 := uint16(45)
	resUint165 := uint16(45)
	argUint166 := uint16(60)
	resUint166 := uint16(50)
	resUint167 := uint16(42)

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
			name: "Applies tags to a non-empty []uint16 field.",
			args: args{
				v: &TestStrStructUint16Sli{
					Field: []uint16{
						30,
						45,
						60,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint16Sli{
				Field: []uint16{
					40,
					45,
					50,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to an empty []uint16 field.",
			args: args{
				v:   &TestStrStructUint16Sli{},
				idx: 0,
			},
			want:    &TestStrStructUint16Sli{},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty []*uint16 field.",
			args: args{
				v: &TestStrStructUint16PtrSli{
					Field: []*uint16{
						&argUint160,
						&argUint161,
						&argUint162,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint16PtrSli{
				Field: []*uint16{
					&resUint160,
					&resUint161,
					&resUint162,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty []*uint16 field.",
			args: args{
				v: &TestStrStructUint16PtrSli{
					Field: []*uint16{
						nil,
						nil,
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint16PtrSli{
				Field: []*uint16{
					nil,
					nil,
					nil,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags (with default) to a non-empty []*uint16 field.",
			args: args{
				v: &TestStrStructUint16PtrSliDef{
					Field: []*uint16{
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint16PtrSliDef{
				Field: []*uint16{
					&resUint163,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]uint16 field.",
			args: args{
				v: &TestStrStructUint16SliPtr{
					Field: &[]uint16{
						30,
						45,
						60,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint16SliPtr{
				Field: &[]uint16{
					40,
					45,
					50,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to an empty *[]uint16 field.",
			args: args{
				v:   &TestStrStructUint16SliPtr{},
				idx: 0,
			},
			want:    &TestStrStructUint16SliPtr{},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]*uint16 field.",
			args: args{
				v: &TestStrStructUint16PtrSliPtr{
					Field: &[]*uint16{
						&argUint164,
						&argUint165,
						&argUint166,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint16PtrSliPtr{
				Field: &[]*uint16{
					&resUint164,
					&resUint165,
					&resUint166,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]*uint16 field.",
			args: args{
				v: &TestStrStructUint16PtrSliPtr{
					Field: &[]*uint16{
						nil,
						nil,
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint16PtrSliPtr{
				Field: &[]*uint16{
					nil,
					nil,
					nil,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags (with default) to a non-empty *[]*uint16 field.",
			args: args{
				v: &TestStrStructUint16PtrSliPtrDef{
					Field: &[]*uint16{
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructUint16PtrSliPtrDef{
				Field: &[]*uint16{
					&resUint167,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeUint16Field(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeUint16Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeUint16Field() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}
