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

	s1 := TestStrStruct{
		Field: " tEst ",
	}
	s2 := TestStrStruct{
		Field: "T",
	}
	s3Field := " tEst "
	s3 := TestStrStructPtr{
		Field: &s3Field,
	}
	s4 := TestStrStructPtr{
		Field: nil,
	}

	type args struct {
		v   reflect.Value
		idx int
	}
	tests := []struct {
		name       string
		args       args
		wantErr    bool
		postTestFn func()
	}{
		{
			name: "Trims, truncates, and lowercases a string field on a struct with the tag.",
			args: args{
				v:   reflect.ValueOf(&s1).Elem(),
				idx: 0,
			},
			wantErr: false,
			postTestFn: func() {
				got := s1.Field
				want := "te"
				if got != want {
					t.Errorf("sanitizeStrField() - failed field - got %+v but wanted %+v", got, want)
				}
			},
		},
		{
			name: "Lowercases a single char string field on a struct with the tag, without throwing an error (max tag doesn't result in mutation).",
			args: args{
				v:   reflect.ValueOf(&s2).Elem(),
				idx: 0,
			},
			wantErr: false,
			postTestFn: func() {
				got := s2.Field
				want := "t"
				if got != want {
					t.Errorf("sanitizeStrField() - failed field - got %+v but wanted %+v", got, want)
				}
			},
		},
		{
			name: "Trims, truncates, and lowercases a string pointer field on a struct with the tag.",
			args: args{
				v:   reflect.ValueOf(&s3).Elem(),
				idx: 0,
			},
			wantErr: false,
			postTestFn: func() {
				got := *s3.Field
				want := "te"
				if got != want {
					t.Errorf("sanitizeStrField() - failed field - got %+v but wanted %+v", got, want)
				}
			},
		},
		{
			name: "Puts a default value for a *string field that was nil on a struct with the tag.",
			args: args{
				v:   reflect.ValueOf(&s4).Elem(),
				idx: 0,
			},
			wantErr: false,
			postTestFn: func() {
				got := *s4.Field
				want := "et"
				if got != want {
					t.Errorf("sanitizeStrField() - failed field - got %+v but wanted %+v", got, want)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeStrField(*s, tt.args.v, tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeStrField() error = %v, wantErr %v", err, tt.wantErr)
			}
			tt.postTestFn()
		})
	}
}
