package sanitize

import (
	"reflect"
	"testing"
)

func Test_sanitizeBoolField(t *testing.T) {
	s, _ := New()
	type TestBoolStructPtr struct {
		Field *bool `san:"def=true"`
	}
	type TestBoolStructPtrBadDef struct {
		Field *bool `san:"def=maybe"`
	}

	s1 := TestBoolStructPtr{
		Field: nil,
	}
	s2 := TestBoolStructPtrBadDef{
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
			name: "Puts a default value for a *bool field that was nil on a struct with the tag.",
			args: args{
				v:   reflect.ValueOf(&s1).Elem(),
				idx: 0,
			},
			wantErr: false,
			postTestFn: func() {
				got := *s1.Field
				want := true
				if got != want {
					t.Errorf("sanitizeBoolField() - failed field - got %+v but wanted %+v", got, want)
				}
			},
		},
		{
			name: "Returns an error for an invalid bool def for a *bool field that was nil on a struct with the tag.",
			args: args{
				v:   reflect.ValueOf(&s2).Elem(),
				idx: 0,
			},
			wantErr:    true,
			postTestFn: func() {},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeBoolField(*s, tt.args.v, tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeBoolField() error = %v, wantErr %v", err, tt.wantErr)
			}
			tt.postTestFn()
		})
	}
}
