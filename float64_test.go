package sanitize

import (
	"reflect"
	"testing"
)

func Test_sanitizeFloat64Field(t *testing.T) {
	s, _ := New()

	type TestFloat64Struct struct {
		Field float64 `san:"max=42.2,min=41.1"`
	}
	type TestFloat64StructNegativeMinTag struct {
		Field float64 `san:"max=41.1,min=-2"`
	}
	type TestFloat64StructNegativeMaxTag struct {
		Field float64 `san:"max=-2,min=42.2"`
	}
	type TestFloat64StructBadMaxMin struct {
		Field float64 `san:"max=41.1,min=42.2"`
	}
	type TestFloat64StructBadMinTag struct {
		Field float64 `san:"max=41.1,min=no"`
	}
	type TestFloat64StructBadMaxTag struct {
		Field float64 `san:"max=no,min=42.2"`
	}
	type TestFloat64StructDef struct {
		Field float64 `san:"def=43.3"`
	}
	type TestFloat64StructPtr struct {
		Field *float64 `san:"max=42.2,min=41.1"`
	}
	type TestFloat64StructPtrDef struct {
		Field *float64 `san:"max=42.2,min=41.1,def=41.1"`
	}
	type TestFloat64StructPtrBadDefMax struct {
		Field *float64 `san:"max=42.2,def=43.3"`
	}
	type TestFloat64StructPtrBadDefTag struct {
		Field *float64 `san:"max=42.2,def=no"`
	}
	type TestFloat64StructPtrBadDefMin struct {
		Field *float64 `san:"min=41.1,def=40.0"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argInt0 := float64(43.3)
	resInt0 := float64(42.2)
	resInt1 := float64(41.1)

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
			name: "Caps an float64 field on a struct with the san:max tag.",
			args: args{
				v: &TestFloat64Struct{
					Field: 43.3,
				},
				idx: 0,
			},
			want: &TestFloat64Struct{
				Field: 42.2,
			},
			wantErr: false,
		},
		{
			name: "Raises an float64 field on a struct with the san:min tag.",
			args: args{
				v: &TestFloat64Struct{
					Field: 40.0,
				},
				idx: 0,
			},
			want: &TestFloat64Struct{
				Field: 41.1,
			},
			wantErr: false,
		},
		{
			name: "Returns an error if a san:min tag on a float64 field is below 0.",
			args: args{
				v: &TestFloat64StructNegativeMinTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestFloat64StructNegativeMinTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a float64 field is below 0.",
			args: args{
				v: &TestFloat64StructNegativeMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestFloat64StructNegativeMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:min tag on a float64 field is not numeric.",
			args: args{
				v: &TestFloat64StructBadMinTag{
					Field: 40.0,
				},
				idx: 0,
			},
			want: &TestFloat64StructBadMinTag{
				Field: 40.0,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a float64 field is not numeric.",
			args: args{
				v: &TestFloat64StructBadMaxTag{
					Field: 40.0,
				},
				idx: 0,
			},
			want: &TestFloat64StructBadMaxTag{
				Field: 40.0,
			},
			wantErr: true,
		},
		{
			name: "Default value does not affect an float64 field on a struct with the tag.",
			args: args{
				v:   &TestFloat64StructDef{},
				idx: 0,
			},
			want:    &TestFloat64StructDef{},
			wantErr: false,
		},
		{
			name: "Returns an error if the maximum value is smaller than the minimum on a struct with the tags.",
			args: args{
				v: &TestFloat64StructBadMaxMin{
					Field: 2.2,
				},
				idx: 0,
			},
			want: &TestFloat64StructBadMaxMin{
				Field: 2.2,
			},
			wantErr: true,
		},
		{
			name: "Ignores a nil *float64 field that was nil on a struct without a def tag.",
			args: args{
				v: &TestFloat64StructPtr{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestFloat64StructPtr{
				Field: nil,
			},
			wantErr: false,
		},
		{
			name: "Caps an *float64 field on a struct with the san:max tag.",
			args: args{
				v: &TestFloat64StructPtrDef{
					Field: &argInt0,
				},
				idx: 0,
			},
			want: &TestFloat64StructPtrDef{
				Field: &resInt0,
			},
			wantErr: false,
		},
		{
			name: "Puts a default value for a *float64 field that was nil on a struct with the tag.",
			args: args{
				v: &TestFloat64StructPtrDef{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestFloat64StructPtrDef{
				Field: &resInt1,
			},
			wantErr: false,
		},
		{
			name: "Returns an error when the def component for a *float64 field is not numeric.",
			args: args{
				v: &TestFloat64StructPtrBadDefTag{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestFloat64StructPtrBadDefTag{
				Field: nil,
			},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the max component are both present, and the def is higher than the max for a *float64 field that was nil on a struct with the tag.",
			args: args{
				v: &TestFloat64StructPtrBadDefMax{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestFloat64StructPtrBadDefMax{},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the low component are both present, and the def is lower than the min for a *float64 field that was nil on a struct with the tag.",
			args: args{
				v: &TestFloat64StructPtrBadDefMin{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestFloat64StructPtrBadDefMin{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeFloat64Field(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeFloat64Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeFloat64Field() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}

func Test_sanitizeFloat64Field_Slice(t *testing.T) {
	s, _ := New()

	type TestStrStructFloat64Sli struct {
		Field []float64 `san:"max=50,min=40"`
	}
	type TestStrStructFloat64PtrSli struct {
		Field []*float64 `san:"max=50,min=40"`
	}
	type TestStrStructFloat64PtrSliDef struct {
		Field []*float64 `san:"max=50,min=40,def=42"`
	}
	type TestStrStructFloat64SliPtr struct {
		Field *[]float64 `san:"max=50,min=40"`
	}
	type TestStrStructFloat64PtrSliPtr struct {
		Field *[]*float64 `san:"max=50,min=40"`
	}
	type TestStrStructFloat64PtrSliPtrDef struct {
		Field *[]*float64 `san:"max=50,min=40,def=42"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argFloat0 := 30.0
	resFloat0 := 40.0
	argFloat1 := 45.0
	resFloat1 := 45.0
	argFloat2 := 60.0
	resFloat2 := 50.0
	resFloat3 := 42.0
	argFloat4 := 30.0
	resFloat4 := 40.0
	argFloat5 := 45.0
	resFloat5 := 45.0
	argFloat6 := 60.0
	resFloat6 := 50.0
	resFloat7 := 42.0

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
			name: "Applies tags to a non-empty []float64 field.",
			args: args{
				v: &TestStrStructFloat64Sli{
					Field: []float64{
						30,
						45,
						60,
					},
				},
				idx: 0,
			},
			want: &TestStrStructFloat64Sli{
				Field: []float64{
					40,
					45,
					50,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to an empty []float64 field.",
			args: args{
				v:   &TestStrStructFloat64Sli{},
				idx: 0,
			},
			want:    &TestStrStructFloat64Sli{},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty []*float64 field.",
			args: args{
				v: &TestStrStructFloat64PtrSli{
					Field: []*float64{
						&argFloat0,
						&argFloat1,
						&argFloat2,
					},
				},
				idx: 0,
			},
			want: &TestStrStructFloat64PtrSli{
				Field: []*float64{
					&resFloat0,
					&resFloat1,
					&resFloat2,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty []*float64 field.",
			args: args{
				v: &TestStrStructFloat64PtrSli{
					Field: []*float64{
						nil,
						nil,
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructFloat64PtrSli{
				Field: []*float64{
					nil,
					nil,
					nil,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags (with default) to a non-empty []*float64 field.",
			args: args{
				v: &TestStrStructFloat64PtrSliDef{
					Field: []*float64{
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructFloat64PtrSliDef{
				Field: []*float64{
					&resFloat3,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]float64 field.",
			args: args{
				v: &TestStrStructFloat64SliPtr{
					Field: &[]float64{
						30,
						45,
						60,
					},
				},
				idx: 0,
			},
			want: &TestStrStructFloat64SliPtr{
				Field: &[]float64{
					40,
					45,
					50,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to an empty *[]float64 field.",
			args: args{
				v:   &TestStrStructFloat64SliPtr{},
				idx: 0,
			},
			want:    &TestStrStructFloat64SliPtr{},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]*float64 field.",
			args: args{
				v: &TestStrStructFloat64PtrSliPtr{
					Field: &[]*float64{
						&argFloat4,
						&argFloat5,
						&argFloat6,
					},
				},
				idx: 0,
			},
			want: &TestStrStructFloat64PtrSliPtr{
				Field: &[]*float64{
					&resFloat4,
					&resFloat5,
					&resFloat6,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]*float64 field.",
			args: args{
				v: &TestStrStructFloat64PtrSliPtr{
					Field: &[]*float64{
						nil,
						nil,
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructFloat64PtrSliPtr{
				Field: &[]*float64{
					nil,
					nil,
					nil,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags (with default) to a non-empty *[]*float64 field.",
			args: args{
				v: &TestStrStructFloat64PtrSliPtrDef{
					Field: &[]*float64{
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructFloat64PtrSliPtrDef{
				Field: &[]*float64{
					&resFloat7,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeFloat64Field(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeFloat64Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeFloat64Field() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}
