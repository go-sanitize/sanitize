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
