package sanitize

import (
	"reflect"
	"testing"
)

func Test_Sanitize_Simple(t *testing.T) {
	type Dog struct {
		Name  string  `san:"max=5,trim,lower"`
		Breed *string `san:"def=unknown"`
	}

	d := Dog{
		Name:  "Borky Borkins",
		Breed: nil,
	}

	unknown := "unknown"
	expected := Dog{
		Name:  "borky",
		Breed: &unknown,
	}

	s, _ := New()
	s.Sanitize(&d)

	if !reflect.DeepEqual(d, expected) {
		gotBreed := "<nil>"
		if d.Breed != nil {
			gotBreed = *d.Breed
		}
		expectedBreed := "<nil>"
		if expected.Breed != nil {
			expectedBreed = *expected.Breed
		}
		t.Errorf(
			"Sanitize() - got { Name: %s, Breed: %s } but wanted { Name: %s, Breed: %s }",
			d.Name,
			gotBreed,
			expected.Name,
			expectedBreed,
		)
	}
}

func Test_Sanitize(t *testing.T) {

	type TestStruct struct {
		StrField     string  `san:"max=2,trim,lower"`
		IntField     int     `san:"min=11,max=12"`
		Int8Field    int8    `san:"min=21,max=22"`
		Int16Field   int16   `san:"min=31,max=32"`
		Int32Field   int32   `san:"min=41,max=42"`
		Int64Field   int64   `san:"min=51,max=52"`
		UintField    uint    `san:"min=61,max=62"`
		Uint8Field   uint8   `san:"min=71,max=72"`
		Uint16Field  uint16  `san:"min=81,max=82"`
		Uint32Field  uint32  `san:"min=91,max=92"`
		Uint64Field  uint64  `san:"min=101,max=102"`
		Float32Field float32 `san:"max=22.3,min=22.2"`
		Float64Field float64 `san:"max=42.3,min=42.2"`
	}

	type TestStructPtr struct {
		StrField     *string  `san:"max=2,trim,lower"`
		IntField     *int     `san:"min=11,max=12"`
		Int8Field    *int8    `san:"min=21,max=22"`
		Int16Field   *int16   `san:"min=31,max=32"`
		Int32Field   *int32   `san:"min=41,max=42"`
		Int64Field   *int64   `san:"min=51,max=52"`
		UintField    *uint    `san:"min=61,max=62"`
		Uint8Field   *uint8   `san:"min=71,max=72"`
		Uint16Field  *uint16  `san:"min=81,max=82"`
		Uint32Field  *uint32  `san:"min=91,max=92"`
		Uint64Field  *uint64  `san:"min=101,max=102"`
		Float32Field *float32 `san:"max=22.3,min=22.2"`
		Float64Field *float64 `san:"max=42.3,min=42.2"`
	}

	type TestStructMixedRecursiveSub struct {
		StrField    string  `san:"max=2,trim,lower"`
		StrPtrField *string `san:"max=2,trim,lower"`
	}

	type TestStructMixedRecursive struct {
		StrField    string  `san:"max=2,trim,lower"`
		StrPtrField *string `san:"max=2,trim,lower"`
		Sub1        TestStructMixedRecursiveSub
		SubPtr1     *TestStructMixedRecursiveSub
		Sub2        TestStruct
		SubPtr2     *TestStructPtr
		SubPtr3     *TestStructPtr
	}

	type TestBadStruct struct {
		Int64Field int64 `san:"min=42,max=41"`
	}

	type TestBadNestedStruct struct {
		Sub TestBadStruct
	}

	s, _ := New()

	arg1 := " PTRTEST "
	res1 := "pt"
	arg2 := " subptrtest1 "
	res2 := "su"
	arg3 := " subptrtest2 "
	res3 := "su"
	arg4 := "world"
	res4 := "wo"
	arg5 := int(10)
	res5 := int(11)
	arg6 := int8(11)
	res6 := int8(21)
	arg7 := int16(11)
	res7 := int16(31)
	arg8 := int32(11)
	res8 := int32(41)
	arg9 := int64(11)
	res9 := int64(51)
	arg10 := uint(10)
	res10 := uint(61)
	arg11 := uint8(11)
	res11 := uint8(71)
	arg12 := uint16(11)
	res12 := uint16(81)
	arg13 := uint32(11)
	res13 := uint32(91)
	arg14 := uint64(11)
	res14 := uint64(101)
	arg15 := float32(90.2)
	res15 := float32(22.3)
	arg16 := 90.2
	res16 := 42.3

	type args struct {
		s interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		want    interface{}
	}{
		{
			name: "Sanitizes a struct that contains all types of fields.",
			args: args{
				s: &TestStructMixedRecursive{
					StrField:    " TEST ",
					StrPtrField: &arg1,
					Sub1: TestStructMixedRecursiveSub{
						StrField:    " subtest1 ",
						StrPtrField: &arg2,
					},
					SubPtr1: &TestStructMixedRecursiveSub{
						StrField:    " subtest2 ",
						StrPtrField: &arg3,
					},
					Sub2: TestStruct{
						StrField:     "hello",
						IntField:     1,
						Int8Field:    1,
						Int16Field:   1,
						Int32Field:   1,
						Int64Field:   1,
						UintField:    1,
						Uint8Field:   1,
						Uint16Field:  1,
						Uint32Field:  1,
						Uint64Field:  1,
						Float32Field: 80.1,
						Float64Field: 80.1,
					},
					SubPtr2: &TestStructPtr{
						StrField:     &arg4,
						IntField:     &arg5,
						Int8Field:    &arg6,
						Int16Field:   &arg7,
						Int32Field:   &arg8,
						Int64Field:   &arg9,
						UintField:    &arg10,
						Uint8Field:   &arg11,
						Uint16Field:  &arg12,
						Uint32Field:  &arg13,
						Uint64Field:  &arg14,
						Float32Field: &arg15,
						Float64Field: &arg16,
					},
				},
			},
			want: &TestStructMixedRecursive{
				StrField:    "te",
				StrPtrField: &res1,
				Sub1: TestStructMixedRecursiveSub{
					StrField:    "su",
					StrPtrField: &res2,
				},
				SubPtr1: &TestStructMixedRecursiveSub{
					StrField:    "su",
					StrPtrField: &res3,
				},
				Sub2: TestStruct{
					StrField:     "he",
					IntField:     11,
					Int8Field:    21,
					Int16Field:   31,
					Int32Field:   41,
					Int64Field:   51,
					UintField:    61,
					Uint8Field:   71,
					Uint16Field:  81,
					Uint32Field:  91,
					Uint64Field:  101,
					Float32Field: 22.3,
					Float64Field: 42.3,
				},
				SubPtr2: &TestStructPtr{
					StrField:     &res4,
					IntField:     &res5,
					Int8Field:    &res6,
					Int16Field:   &res7,
					Int32Field:   &res8,
					Int64Field:   &res9,
					UintField:    &res10,
					Uint8Field:   &res11,
					Uint16Field:  &res12,
					Uint32Field:  &res13,
					Uint64Field:  &res14,
					Float32Field: &res15,
					Float64Field: &res16,
				},
			},
			wantErr: false,
		},
		{
			name: "Returns an error if there are problems with the struct tags",
			args: args{
				s: &TestBadStruct{
					Int64Field: 10,
				},
			},
			want: &TestBadStruct{
				Int64Field: 10,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if there are problems with a nested struct tags",
			args: args{
				s: &TestBadNestedStruct{
					Sub: TestBadStruct{
						Int64Field: 10,
					},
				},
			},
			want: &TestBadNestedStruct{
				Sub: TestBadStruct{
					Int64Field: 10,
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := s.Sanitize(tt.args.s); (err != nil) != tt.wantErr {
				t.Errorf("Sanitize() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.s, tt.want) {
				t.Errorf("Sanitize() - got %+v but wanted %+v", tt.args.s, tt.want)
			}
		})
	}
}
