package sanitize

import (
	"reflect"
	"testing"
)

type TestStruct struct {
	StrField     string  `san:"max=2,trim,lower"`
	Int64Field   int64   `san:"min=41,max=42"`
	Float64Field float64 `san:"max=42.3,min=42.2"`
}

type TestStructPtr struct {
	StrField     *string  `san:"max=2,trim,lower"`
	Int64Field   *int64   `san:"min=41,max=42"`
	Float64Field *float64 `san:"max=42.3,min=42.2"`
}

type TestStructMixedRecursive struct {
	StrField    string  `san:"max=2,trim,lower"`
	StrPtrField *string `san:"max=2,trim,lower"`
	Sub         TestStructMixedRecursiveSub
	SubPtr      *TestStructMixedRecursiveSub
}
type TestStructMixedRecursiveSub struct {
	StrField    string  `san:"max=2,trim,lower"`
	StrPtrField *string `san:"max=2,trim,lower"`
}

func Test_Struct(t *testing.T) {
	ts1 := TestStruct{
		StrField:     " tEst ",
		Int64Field:   43,
		Float64Field: 42.4,
	}
	ts2Str := " tEst "
	ts2Int := int64(43)
	ts2Float := float64(42.4)
	ts2 := TestStructPtr{
		StrField:     &ts2Str,
		Int64Field:   &ts2Int,
		Float64Field: &ts2Float,
	}

	type args struct {
		s interface{}
	}
	tests := []struct {
		name       string
		args       args
		wantErr    bool
		want       TestStruct
		postTestFn func()
	}{
		{
			name: "Sanitizes a struct that contains a string field, int64 field, and float64 field.",
			args: args{
				s: &ts1,
			},
			wantErr: false,
			postTestFn: func() {
				if ts1.StrField != "te" {
					t.Error("sanitizeRec() - failed string field")
				}
				if ts1.Int64Field != 42 {
					t.Error("sanitizeRec() - failed int64 field")
				}
				if ts1.Float64Field != 42.3 {
					t.Error("sanitizeRec() - failed int64 field")
				}
			},
		},
		{
			name: "Sanitizes a struct that contains a *string field, *int64 field, and *float64 field.",
			args: args{
				s: &ts2,
			},
			wantErr: false,
			postTestFn: func() {
				if *ts2.StrField != "te" {
					t.Error("sanitizeRec() - failed *string field")
				}
				if *ts2.Int64Field != 42 {
					t.Error("sanitizeRec() - failed *int64 field")
				}
				if *ts2.Float64Field != 42.3 {
					t.Error("sanitizeRec() - failed *int64 field")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Struct(tt.args.s); (err != nil) != tt.wantErr {
				t.Errorf("Sanitize() error = %v, wantErr %v", err, tt.wantErr)
			}
			tt.postTestFn()
		})
	}
}

// Tests that, given a reflect.Value representing a struct field, it will
// process it. Includes some structs which have pointer fields.
func Test_sanitizeRec(t *testing.T) {
	ts1 := TestStruct{
		StrField:     " test ",
		Int64Field:   43,
		Float64Field: 42.4,
	}
	ts2Str := " test "
	ts2Int64 := int64(43)
	ts2Float64 := 42.4
	ts2 := TestStructPtr{
		StrField:     &ts2Str,
		Int64Field:   &ts2Int64,
		Float64Field: &ts2Float64,
	}

	// Testing recursion with and without pointers
	ts3StrPtrField := " tEst "
	ts3SubStrPtrField := " tEst "
	ts3SubPtrStrPtrField := " tEst "
	ts3SubPtr := TestStructMixedRecursiveSub{
		StrField:    " tEst ",
		StrPtrField: &ts3SubPtrStrPtrField,
	}
	ts3 := TestStructMixedRecursive{
		StrField:    " tEst ",
		StrPtrField: &ts3StrPtrField,
		Sub: TestStructMixedRecursiveSub{
			StrField:    " tEst ",
			StrPtrField: &ts3SubStrPtrField,
		},
		SubPtr: &ts3SubPtr,
	}

	type args struct {
		v reflect.Value
	}
	tests := []struct {
		name       string
		args       args
		wantErr    bool
		postTestFn func()
	}{
		{
			name: "Sanitizes a struct that contains a string field, int64 field, and float64 field.",
			args: args{
				v: reflect.ValueOf(&ts1).Elem(), // calling code (Sanitize fn) would call Elem() internally to package
			},
			wantErr: false,
			postTestFn: func() {
				if ts1.StrField != "te" {
					t.Error("sanitizeRec() - failed string field")
				}
				if ts1.Int64Field != 42 {
					t.Error("sanitizeRec() - failed int64 field")
				}
				if ts1.Float64Field != 42.3 {
					t.Error("sanitizeRec() - failed int64 field")
				}
			},
		},
		{
			name: "Sanitizes a struct that contains a string field, int64 field, and float64 field, all as pointers.",
			args: args{
				v: reflect.ValueOf(&ts2).Elem(), // calling code (Sanitize fn) would call Elem() internally to package
			},
			wantErr: false,
			postTestFn: func() {
				if *ts2.StrField != "te" {
					t.Error("sanitizeRec() - failed string ptr field")
				}
				if *ts2.Int64Field != 42 {
					t.Error("sanitizeRec() - failed int64 ptr field")
				}
				if *ts2.Float64Field != 42.3 {
					t.Error("sanitizeRec() - failed int64 ptr field")
				}
			},
		},
		{
			name: "Sanitizes a struct that contains a mixture of non-pointer fields, pointer fields, including recursive structs with and without pointers.",
			args: args{
				v: reflect.ValueOf(&ts3).Elem(), // calling code (Sanitize fn) would call Elem() internally to package
			},
			wantErr: false,
			postTestFn: func() {
				if ts3.StrField != "te" {
					t.Error("sanitizeRec() - failed string field")
				}
				if *ts3.StrPtrField != "te" {
					t.Error("sanitizeRec() - failed *string field")
				}
				if ts3.Sub.StrField != "te" {
					t.Error("sanitizeRec() - failed Sub.string field")
				}
				if *ts3.Sub.StrPtrField != "te" {
					t.Error("sanitizeRec() - failed *int64 field")
				}
				ts3SubPtr := *ts3.SubPtr
				if ts3SubPtr.StrField != "te" {
					t.Error("sanitizeRec() - failed SubPtr.string field")
				}
				if *ts3SubPtr.StrPtrField != "te" {
					t.Error("sanitizeRec() - failed SubPtr.*string field")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeRec(tt.args.v); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeRec() error = %v, wantErr %v", err, tt.wantErr)
			}
			tt.postTestFn()
		})
	}
}

// Tests that it will fully process the string field of the test struct.
func Test_sanitizeStrField(t *testing.T) {
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
			if err := sanitizeStrField(tt.args.v, tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeStrField() error = %v, wantErr %v", err, tt.wantErr)
			}
			tt.postTestFn()
		})
	}
}

// Tests that it will fully process the int64 field of the test struct.
func Test_sanitizeInt64Field(t *testing.T) {
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
			if err := sanitizeInt64Field(tt.args.v, tt.args.idx); (err != nil) != tt.wantErr {
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
			if err := sanitizeInt64Field(tt.args.v, tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeInt64Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(*tt.sFn(), tt.want) {
				t.Errorf(`sanitizeInt64Field() = %+v, got %+v`, *tt.sFn(), tt.want)
			}
		})
	}
}

// Tests that it will fully process the int64 field of the test struct.
func Test_sanitizeFloat64Field(t *testing.T) {
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
			if err := sanitizeFloat64Field(tt.args.v, tt.args.idx); (err != nil) != tt.wantErr {
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
			if err := sanitizeFloat64Field(tt.args.structValue, tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeFloat64Field() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(*tt.sFn(), tt.want) {
				t.Errorf(`sanitizeFloat64Field() = %+v, got %+v`, *tt.sFn(), tt.want)
			}
		})
	}
}

// Tests that it will fully process the int64 field of the test struct.
func Test_sanitizeBoolField(t *testing.T) {
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
			if err := sanitizeBoolField(tt.args.v, tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeBoolField() error = %v, wantErr %v", err, tt.wantErr)
			}
			tt.postTestFn()
		})
	}
}
