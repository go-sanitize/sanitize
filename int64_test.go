package sanitize

import (
	"reflect"
	"testing"
)

func Test_sanitizeInt64Field(t *testing.T) {
	s, _ := New()
	type TestInt64Struct struct {
		Field int64 `san:"max=42,min=41"`
	}
	type TestInt64StructPtr struct {
		Field *int64 `san:"max=42,min=41,def=41"`
	}
	type TestInt64StructPtrBadDefMax struct {
		Field *int64 `san:"max=42,def=43"`
	}
	type TestInt64StructPtrBadDefMin struct {
		Field *int64 `san:"min=41,def=40"`
	}

	s1 := TestInt64Struct{
		Field: 43,
	}
	s2 := TestInt64Struct{
		Field: 40,
	}
	s3Field := int64(43)
	s3 := TestInt64StructPtr{
		Field: &s3Field,
	}
	s4 := TestInt64StructPtr{
		Field: nil,
	}
	s5 := TestInt64StructPtrBadDefMax{
		Field: nil,
	}
	s6 := TestInt64StructPtrBadDefMin{
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
			name: "Caps an int64 field on a struct with the san:max tag.",
			args: args{
				v:   reflect.ValueOf(&s1).Elem(),
				idx: 0,
			},
			wantErr: false,
			postTestFn: func() {
				got := s1.Field
				want := int64(42)
				if got != want {
					t.Errorf("sanitizeInt64Field() - failed field - got %+v but wanted %+v", got, want)
				}
			},
		},
		{
			name: "Raises an int64 field on a struct with the san:min tag.",
			args: args{
				v:   reflect.ValueOf(&s2).Elem(),
				idx: 0,
			},
			wantErr: false,
			postTestFn: func() {
				got := s2.Field
				want := int64(41)
				if got != want {
					t.Errorf("sanitizeInt64Field() - failed field - got %+v but wanted %+v", got, want)
				}
			},
		},
		{
			name: "Caps an *int64 field on a struct with the san:max tag.",
			args: args{
				v:   reflect.ValueOf(&s3).Elem(),
				idx: 0,
			},
			wantErr: false,
			postTestFn: func() {
				got := *s3.Field
				want := int64(42)
				if got != want {
					t.Errorf("sanitizeInt64Field() - failed field - got %+v but wanted %+v", got, want)
				}
			},
		},
		{
			name: "Puts a default value for a *int64 field that was nil on a struct with the tag.",
			args: args{
				v:   reflect.ValueOf(&s4).Elem(),
				idx: 0,
			},
			wantErr: false,
			postTestFn: func() {
				got := *s4.Field
				want := int64(41)
				if got != want {
					t.Errorf("sanitizeInt64Field() - failed field - got %+v but wanted %+v", got, want)
				}
			},
		},
		{
			name: "Returns an error when the def component and the max component are both present, and the def is higher than the max for a *int64 field that was nil on a struct with the tag.",
			args: args{
				v:   reflect.ValueOf(&s5).Elem(),
				idx: 0,
			},
			wantErr:    true,
			postTestFn: func() {},
		},
		{
			name: "Returns an error when the def component and the low component are both present, and the def is lower than the min for a *int64 field that was nil on a struct with the tag.",
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
			if err := sanitizeInt64Field(*s, tt.args.v, tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeInt64Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			tt.postTestFn()
		})
	}

	// Invalid tags
	type TestInt64StructInvalidTag struct {
		Field int64 `san:"max=41,min=42"`
	}

	si1 := TestInt64StructInvalidTag{
		Field: 42,
	}

	type argsi struct {
		v   reflect.Value
		idx int
	}
	testsi := []struct {
		name    string
		args    argsi
		wantErr bool
		want    TestInt64StructInvalidTag
		sFn     func() *TestInt64StructInvalidTag
	}{
		{
			name: "Returns an error when asked to sanitize a struct with an invalid min, max pair on an int64 field.",
			args: argsi{
				v:   reflect.ValueOf(&si1).Elem(),
				idx: 0,
			},
			wantErr: true,
			want: TestInt64StructInvalidTag{ // no mutation expected
				Field: 42,
			},
			sFn: func() *TestInt64StructInvalidTag {
				return &si1
			},
		},
	}
	for _, tt := range testsi {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeInt64Field(*s, tt.args.v, tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeInt64Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(*tt.sFn(), tt.want) {
				t.Errorf(`sanitizeInt64Field() = %+v, got %+v`, *tt.sFn(), tt.want)
			}
		})
	}
}
