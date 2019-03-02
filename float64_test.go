package sanitize

import (
	"reflect"
	"testing"
)

func Test_sanitizeFloat64Field(t *testing.T) {
	s, _ := New()
	type TestFloat64Struct struct {
		Field float64 `san:"max=42.3,min=42.2"`
	}
	type TestFloat64StructPtr struct {
		Field *float64 `san:"max=42.3,min=42.2,def=42.2"`
	}
	type TestFloat64StructPtrBadDefMax struct {
		Field *float64 `san:"def=42.4,max=42.3"`
	}
	type TestFloat64StructPtrBadDefMin struct {
		Field *float64 `san:"def=42.1,min=42.2"`
	}

	s1 := TestFloat64Struct{
		Field: 42.4,
	}
	s2 := TestFloat64Struct{
		Field: 42.1,
	}
	s3Field := 42.4
	s3 := TestFloat64StructPtr{
		Field: &s3Field,
	}
	s4 := TestFloat64StructPtr{
		Field: nil,
	}
	s5 := TestFloat64StructPtrBadDefMax{
		Field: nil,
	}
	s6 := TestFloat64StructPtrBadDefMin{
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
			name: "Caps a float64 field on a struct with the san:max tag.",
			args: args{
				v:   reflect.ValueOf(&s1).Elem(),
				idx: 0,
			},
			wantErr: false,
			postTestFn: func() {
				got := s1.Field
				want := float64(42.3)
				if got != want {
					t.Errorf("sanitizeFloat64Field() - failed field - got %+v but wanted %+v", got, want)
				}
			},
		},
		{
			name: "Raises a float64 field on a struct with the san:min tag.",
			args: args{
				v:   reflect.ValueOf(&s2).Elem(),
				idx: 0,
			},
			wantErr: false,
			postTestFn: func() {
				got := s2.Field
				want := float64(42.2)
				if got != want {
					t.Errorf("sanitizeFloat64Field() - failed field - got %+v but wanted %+v", got, want)
				}
			},
		},
		{
			name: "Caps a *float64 field on a struct with the san:max tag.",
			args: args{
				v:   reflect.ValueOf(&s3).Elem(),
				idx: 0,
			},
			wantErr: false,
			postTestFn: func() {
				got := *s3.Field
				want := float64(42.3)
				if got != want {
					t.Errorf("sanitizeFloat64Field() - failed field - got %+v but wanted %+v", got, want)
				}
			},
		},
		{
			name: "Puts a default value for a *float64 field that was nil on a struct with the tag.",
			args: args{
				v:   reflect.ValueOf(&s4).Elem(),
				idx: 0,
			},
			wantErr: false,
			postTestFn: func() {
				got := *s4.Field
				want := float64(42.2)
				if got != want {
					t.Errorf("sanitizeFloat64Field() - failed field - got %+v but wanted %+v", got, want)
				}
			},
		},
		{
			name: "Returns an error when the def component and the max component are both present, and the def is higher than the max for a *float64 field that was nil on a struct with the tag.",
			args: args{
				v:   reflect.ValueOf(&s5).Elem(),
				idx: 0,
			},
			wantErr:    true,
			postTestFn: func() {},
		},
		{
			name: "Returns an error when the def component and the low component are both present, and the def is lower than the min for a *float64 field that was nil on a struct with the tag.",
			args: args{
				v:   reflect.ValueOf(&s6).Elem(),
				idx: 0,
			},
			wantErr:    true,
			postTestFn: func() {},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeFloat64Field(*s, tt.args.v, tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeFloat64Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			tt.postTestFn()
		})
	}

	// Invalid tags
	type TestFloat64StructInvalidTag struct {
		Field float64 `san:"min=42.3,max=42.2"`
	}

	si1 := TestFloat64StructInvalidTag{
		Field: 42.123,
	}

	type argsi struct {
		structValue reflect.Value
		idx         int
	}
	testsi := []struct {
		name    string
		args    argsi
		wantErr bool
		want    TestFloat64StructInvalidTag
		sFn     func() *TestFloat64StructInvalidTag
	}{
		{
			name: "Returns an error when asked to sanitize a struct with an invalid min, max pair on a float64 field.",
			args: argsi{
				structValue: reflect.ValueOf(&si1).Elem(),
				idx:         0,
			},
			wantErr: true,
			want: TestFloat64StructInvalidTag{ // no mutation expected
				Field: 42.123,
			},
			sFn: func() *TestFloat64StructInvalidTag {
				return &si1
			},
		},
	}
	for _, tt := range testsi {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeFloat64Field(*s, tt.args.structValue, tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeFloat64Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(*tt.sFn(), tt.want) {
				t.Errorf(`sanitizeFloat64Field() = %+v, got %+v`, *tt.sFn(), tt.want)
			}
		})
	}
}
