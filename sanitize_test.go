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
		Int64Field   int64   `san:"min=41,max=42"`
		Float64Field float64 `san:"max=42.3,min=42.2"`
	}

	type TestStructPtr struct {
		StrField     *string  `san:"max=2,trim,lower"`
		Int64Field   *int64   `san:"min=41,max=42"`
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
	arg5 := int64(11)
	res5 := int64(41)
	arg6 := 90.2
	res6 := 42.3

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
						Int64Field:   10,
						Float64Field: 80.1,
					},
					SubPtr2: &TestStructPtr{
						StrField:     &arg4,
						Int64Field:   &arg5,
						Float64Field: &arg6,
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
					Int64Field:   41,
					Float64Field: 42.3,
				},
				SubPtr2: &TestStructPtr{
					StrField:     &res4,
					Int64Field:   &res5,
					Float64Field: &res6,
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
