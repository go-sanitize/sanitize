package sanitize

import (
	"reflect"
	"testing"
)

func Test_sanitizeBoolField(t *testing.T) {
	s, _ := New()

	type TestBoolStructDefTrue struct {
		Field bool `san:"def=true"`
	}
	type TestBoolStructDefFalse struct {
		Field bool `san:"def=false"`
	}
	type TestBoolStructBadDef struct {
		Field bool `san:"def=maybe"`
	}
	type TestBoolStructPtrDefTrue struct {
		Field *bool `san:"def=true"`
	}
	type TestBoolStructPtrDefFalse struct {
		Field *bool `san:"def=false"`
	}
	type TestBoolStructPtrBadDef struct {
		Field *bool `san:"def=maybe"`
	}

	boolFalse := false
	boolTrue := true

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
			name: "Default value (true) should not modify a bool field.",
			args: args{
				v: &TestBoolStructDefTrue{
					Field: false,
				},
				idx: 0,
			},
			want: &TestBoolStructDefTrue{
				Field: false,
			},
			wantErr: false,
		},
		{
			name: "Default value (false) should not modify a bool field.",
			args: args{
				v: &TestBoolStructDefFalse{
					Field: true,
				},
				idx: 0,
			},
			want: &TestBoolStructDefFalse{
				Field: true,
			},
			wantErr: false,
		},
		{
			name: "Default value (invalid) should not modify a bool field.",
			args: args{
				v: &TestBoolStructBadDef{
					Field: false,
				},
				idx: 0,
			},
			want: &TestBoolStructBadDef{
				Field: false,
			},
			wantErr: false,
		},
		{
			name: "Puts a default value (true) for a *bool field that was nil on a struct with the tag.",
			args: args{
				v: &TestBoolStructPtrDefTrue{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestBoolStructPtrDefTrue{
				Field: &boolTrue,
			},
			wantErr: false,
		},
		{
			name: "Puts a default value (false) for a *bool field that was nil on a struct with the tag.",
			args: args{
				v: &TestBoolStructPtrDefFalse{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestBoolStructPtrDefFalse{
				Field: &boolFalse,
			},
			wantErr: false,
		},
		{
			name: "Returns an error for an invalid bool def for a *bool field that was nil on a struct with the tag.",
			args: args{
				v: &TestBoolStructPtrBadDef{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestBoolStructPtrBadDef{
				Field: nil,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeBoolField(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeBoolField() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeBoolField() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}

func Test_sanitizeBoolField_Slice(t *testing.T) {
	s, _ := New()

	type TestStrStructBoolSli struct {
		Field []bool `san:""`
	}
	type TestStrStructBoolPtrSli struct {
		Field []*bool `san:""`
	}
	type TestStrStructBoolPtrSliDef struct {
		Field []*bool `san:"def=true"`
	}
	type TestStrStructBoolSliPtr struct {
		Field *[]bool `san:""`
	}
	type TestStrStructBoolPtrSliPtr struct {
		Field *[]*bool `san:""`
	}
	type TestStrStructBoolPtrSliPtrDef struct {
		Field *[]*bool `san:"def=true"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argString0 := false
	resString0 := false
	argString1 := true
	resString1 := true
	argString2 := false
	resString2 := false
	resString3 := true
	argString4 := false
	resString4 := false
	argString5 := true
	resString5 := true
	argString6 := false
	resString6 := false
	resString7 := true

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
			name: "Applies tags to a non-empty []bool field.",
			args: args{
				v: &TestStrStructBoolSli{
					Field: []bool{
						false,
						true,
						false,
					},
				},
				idx: 0,
			},
			want: &TestStrStructBoolSli{
				Field: []bool{
					false,
					true,
					false,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to an empty []bool field.",
			args: args{
				v:   &TestStrStructBoolSli{},
				idx: 0,
			},
			want:    &TestStrStructBoolSli{},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty []*bool field.",
			args: args{
				v: &TestStrStructBoolPtrSli{
					Field: []*bool{
						&argString0,
						&argString1,
						&argString2,
					},
				},
				idx: 0,
			},
			want: &TestStrStructBoolPtrSli{
				Field: []*bool{
					&resString0,
					&resString1,
					&resString2,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty []*bool field.",
			args: args{
				v: &TestStrStructBoolPtrSli{
					Field: []*bool{
						nil,
						nil,
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructBoolPtrSli{
				Field: []*bool{
					nil,
					nil,
					nil,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags (with default) to a non-empty []*bool field.",
			args: args{
				v: &TestStrStructBoolPtrSliDef{
					Field: []*bool{
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructBoolPtrSliDef{
				Field: []*bool{
					&resString3,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]bool field.",
			args: args{
				v: &TestStrStructBoolSliPtr{
					Field: &[]bool{
						false,
						true,
						false,
					},
				},
				idx: 0,
			},
			want: &TestStrStructBoolSliPtr{
				Field: &[]bool{
					false,
					true,
					false,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to an empty *[]bool field.",
			args: args{
				v:   &TestStrStructBoolSliPtr{},
				idx: 0,
			},
			want:    &TestStrStructBoolSliPtr{},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]*bool field.",
			args: args{
				v: &TestStrStructBoolPtrSliPtr{
					Field: &[]*bool{
						&argString4,
						&argString5,
						&argString6,
					},
				},
				idx: 0,
			},
			want: &TestStrStructBoolPtrSliPtr{
				Field: &[]*bool{
					&resString4,
					&resString5,
					&resString6,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]*bool field.",
			args: args{
				v: &TestStrStructBoolPtrSliPtr{
					Field: &[]*bool{
						nil,
						nil,
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructBoolPtrSliPtr{
				Field: &[]*bool{
					nil,
					nil,
					nil,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags (with default) to a non-empty *[]*bool field.",
			args: args{
				v: &TestStrStructBoolPtrSliPtrDef{
					Field: &[]*bool{
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructBoolPtrSliPtrDef{
				Field: &[]*bool{
					&resString7,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeBoolField(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeBoolField() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeBoolField() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}
