package sanitize

import (
	"reflect"
	"testing"
)

func Test_sanitizeFloat32Field(t *testing.T) {
	s, _ := New()

	type TestFloat32Struct struct {
		Field float32 `san:"max=42.2,min=41.1"`
	}
	type TestFloat32StructNegativeMinTag struct {
		Field float32 `san:"max=41.1,min=-2"`
	}
	type TestFloat32StructNegativeMaxTag struct {
		Field float32 `san:"max=-2,min=42.2"`
	}
	type TestFloat32StructBadMaxMin struct {
		Field float32 `san:"max=41.1,min=42.2"`
	}
	type TestFloat32StructBadMinTag struct {
		Field float32 `san:"max=41.1,min=no"`
	}
	type TestFloat32StructBadMaxTag struct {
		Field float32 `san:"max=no,min=42.2"`
	}
	type TestFloat32StructDef struct {
		Field float32 `san:"def=43.3"`
	}
	type TestFloat32StructPtr struct {
		Field *float32 `san:"max=42.2,min=41.1"`
	}
	type TestFloat32StructPtrDef struct {
		Field *float32 `san:"max=42.2,min=41.1,def=41.1"`
	}
	type TestFloat32StructPtrBadDefMax struct {
		Field *float32 `san:"max=42.2,def=43.3"`
	}
	type TestFloat32StructPtrBadDefTag struct {
		Field *float32 `san:"max=42.2,def=no"`
	}
	type TestFloat32StructPtrBadDefMin struct {
		Field *float32 `san:"min=41.1,def=40.0"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argInt0 := float32(43.3)
	resInt0 := float32(42.2)
	resInt1 := float32(41.1)

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
			name: "Caps an float32 field on a struct with the san:max tag.",
			args: args{
				v: &TestFloat32Struct{
					Field: 43.3,
				},
				idx: 0,
			},
			want: &TestFloat32Struct{
				Field: 42.2,
			},
			wantErr: false,
		},
		{
			name: "Raises an float32 field on a struct with the san:min tag.",
			args: args{
				v: &TestFloat32Struct{
					Field: 40.0,
				},
				idx: 0,
			},
			want: &TestFloat32Struct{
				Field: 41.1,
			},
			wantErr: false,
		},
		{
			name: "Returns an error if a san:min tag on a float32 field is below 0.",
			args: args{
				v: &TestFloat32StructNegativeMinTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestFloat32StructNegativeMinTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a float32 field is below 0.",
			args: args{
				v: &TestFloat32StructNegativeMaxTag{
					Field: 40,
				},
				idx: 0,
			},
			want: &TestFloat32StructNegativeMaxTag{
				Field: 40,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:min tag on a float32 field is not numeric.",
			args: args{
				v: &TestFloat32StructBadMinTag{
					Field: 40.0,
				},
				idx: 0,
			},
			want: &TestFloat32StructBadMinTag{
				Field: 40.0,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if a san:max tag on a float32 field is not numeric.",
			args: args{
				v: &TestFloat32StructBadMaxTag{
					Field: 40.0,
				},
				idx: 0,
			},
			want: &TestFloat32StructBadMaxTag{
				Field: 40.0,
			},
			wantErr: true,
		},
		{
			name: "Default value does not affect an float32 field on a struct with the tag.",
			args: args{
				v:   &TestFloat32StructDef{},
				idx: 0,
			},
			want:    &TestFloat32StructDef{},
			wantErr: false,
		},
		{
			name: "Returns an error if the maximum value is smaller than the minimum on a struct with the tags.",
			args: args{
				v: &TestFloat32StructBadMaxMin{
					Field: 2.2,
				},
				idx: 0,
			},
			want: &TestFloat32StructBadMaxMin{
				Field: 2.2,
			},
			wantErr: true,
		},
		{
			name: "Ignores a nil *float32 field that was nil on a struct without a def tag.",
			args: args{
				v: &TestFloat32StructPtr{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestFloat32StructPtr{
				Field: nil,
			},
			wantErr: false,
		},
		{
			name: "Caps an *float32 field on a struct with the san:max tag.",
			args: args{
				v: &TestFloat32StructPtrDef{
					Field: &argInt0,
				},
				idx: 0,
			},
			want: &TestFloat32StructPtrDef{
				Field: &resInt0,
			},
			wantErr: false,
		},
		{
			name: "Puts a default value for a *float32 field that was nil on a struct with the tag.",
			args: args{
				v: &TestFloat32StructPtrDef{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestFloat32StructPtrDef{
				Field: &resInt1,
			},
			wantErr: false,
		},
		{
			name: "Returns an error when the def component for a *float32 field is not numeric.",
			args: args{
				v: &TestFloat32StructPtrBadDefTag{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestFloat32StructPtrBadDefTag{
				Field: nil,
			},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the max component are both present, and the def is higher than the max for a *float32 field that was nil on a struct with the tag.",
			args: args{
				v: &TestFloat32StructPtrBadDefMax{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestFloat32StructPtrBadDefMax{},
			wantErr: true,
		},
		{
			name: "Returns an error when the def component and the low component are both present, and the def is lower than the min for a *float32 field that was nil on a struct with the tag.",
			args: args{
				v: &TestFloat32StructPtrBadDefMin{
					Field: nil,
				},
				idx: 0,
			},
			want:    &TestFloat32StructPtrBadDefMin{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeFloat32Field(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeFloat32Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeFloat32Field() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}

func Test_sanitizeFloat32Field_Slice(t *testing.T) {
	s, _ := New()

	type TestStrStructFloat32Sli struct {
		Field []float32 `san:"max=50,min=40"`
	}
	type TestStrStructFloat32PtrSli struct {
		Field []*float32 `san:"max=50,min=40"`
	}
	type TestStrStructFloat32PtrSliDef struct {
		Field []*float32 `san:"max=50,min=40,def=42"`
	}
	type TestStrStructFloat32SliPtr struct {
		Field *[]float32 `san:"max=50,min=40"`
	}
	type TestStrStructFloat32PtrSliPtr struct {
		Field *[]*float32 `san:"max=50,min=40"`
	}
	type TestStrStructFloat32PtrSliPtrDef struct {
		Field *[]*float32 `san:"max=50,min=40,def=42"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argFloat0 := float32(30.0)
	resFloat0 := float32(40.0)
	argFloat1 := float32(45.0)
	resFloat1 := float32(45.0)
	argFloat2 := float32(60.0)
	resFloat2 := float32(50.0)
	resFloat3 := float32(42.0)
	argFloat4 := float32(30.0)
	resFloat4 := float32(40.0)
	argFloat5 := float32(45.0)
	resFloat5 := float32(45.0)
	argFloat6 := float32(60.0)
	resFloat6 := float32(50.0)
	resFloat7 := float32(42.0)

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
			name: "Applies tags to a non-empty []float32 field.",
			args: args{
				v: &TestStrStructFloat32Sli{
					Field: []float32{
						30,
						45,
						60,
					},
				},
				idx: 0,
			},
			want: &TestStrStructFloat32Sli{
				Field: []float32{
					40,
					45,
					50,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to an empty []float32 field.",
			args: args{
				v:   &TestStrStructFloat32Sli{},
				idx: 0,
			},
			want:    &TestStrStructFloat32Sli{},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty []*float32 field.",
			args: args{
				v: &TestStrStructFloat32PtrSli{
					Field: []*float32{
						&argFloat0,
						&argFloat1,
						&argFloat2,
					},
				},
				idx: 0,
			},
			want: &TestStrStructFloat32PtrSli{
				Field: []*float32{
					&resFloat0,
					&resFloat1,
					&resFloat2,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty []*float32 field.",
			args: args{
				v: &TestStrStructFloat32PtrSli{
					Field: []*float32{
						nil,
						nil,
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructFloat32PtrSli{
				Field: []*float32{
					nil,
					nil,
					nil,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags (with default) to a non-empty []*float32 field.",
			args: args{
				v: &TestStrStructFloat32PtrSliDef{
					Field: []*float32{
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructFloat32PtrSliDef{
				Field: []*float32{
					&resFloat3,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]float32 field.",
			args: args{
				v: &TestStrStructFloat32SliPtr{
					Field: &[]float32{
						30,
						45,
						60,
					},
				},
				idx: 0,
			},
			want: &TestStrStructFloat32SliPtr{
				Field: &[]float32{
					40,
					45,
					50,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to an empty *[]float32 field.",
			args: args{
				v:   &TestStrStructFloat32SliPtr{},
				idx: 0,
			},
			want:    &TestStrStructFloat32SliPtr{},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]*float32 field.",
			args: args{
				v: &TestStrStructFloat32PtrSliPtr{
					Field: &[]*float32{
						&argFloat4,
						&argFloat5,
						&argFloat6,
					},
				},
				idx: 0,
			},
			want: &TestStrStructFloat32PtrSliPtr{
				Field: &[]*float32{
					&resFloat4,
					&resFloat5,
					&resFloat6,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]*float32 field.",
			args: args{
				v: &TestStrStructFloat32PtrSliPtr{
					Field: &[]*float32{
						nil,
						nil,
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructFloat32PtrSliPtr{
				Field: &[]*float32{
					nil,
					nil,
					nil,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags (with default) to a non-empty *[]*float32 field.",
			args: args{
				v: &TestStrStructFloat32PtrSliPtrDef{
					Field: &[]*float32{
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructFloat32PtrSliPtrDef{
				Field: &[]*float32{
					&resFloat7,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeFloat32Field(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeFloat32Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeFloat32Field() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}
