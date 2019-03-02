package sanitize

import (
	"reflect"
	"testing"
)

func Test_sanitizeStrField(t *testing.T) {
	s, _ := New()

	type TestStrStruct struct {
		Field string `san:"max=2,trim,lower"`
	}
	type TestStrStructPtr struct {
		Field *string `san:"max=2,trim,lower,def=et"`
	}

	string1 := " tEst "
	string2 := "te"
	string3 := "et"

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
			name: "Trims, truncates, and lowercases a string field on a struct with the tag.",
			args: args{
				v: &TestStrStruct{
					Field: " tEst ",
				},
				idx: 0,
			},
			want: &TestStrStruct{
				Field: "te",
			},
			wantErr: false,
		},
		{
			name: "Lowercases a single char string field on a struct with the tag, without throwing an error (max tag doesn't result in mutation).",
			args: args{
				v: &TestStrStruct{
					Field: "T",
				},
				idx: 0,
			},
			want: &TestStrStruct{
				Field: "t",
			},
			wantErr: false,
		},
		{
			name: "Trims, truncates, and lowercases a string pointer field on a struct with the tag.",
			args: args{
				v: &TestStrStructPtr{
					Field: &string1, // ' tEst '
				},
				idx: 0,
			},
			want: &TestStrStructPtr{
				Field: &string2, // te
			},
			wantErr: false,
		},
		{
			name: "Puts a default value for a *string field that was nil on a struct with the tag.",
			args: args{
				v: &TestStrStructPtr{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestStrStructPtr{
				Field: &string3, // et
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeStrField(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeStrField() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeStrField() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}
