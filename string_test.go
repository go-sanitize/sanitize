package sanitize

import (
	"reflect"
	"testing"
)

func Test_sanitizeStrField(t *testing.T) {
	s, _ := New()

	type TestStrStructNoOp struct {
		Field string
	}
	type TestStrStructTrunc struct {
		Field string `san:"max=2"`
	}
	type TestStrStructTrim struct {
		Field string `san:"trim"`
	}
	type TestStrStructLower struct {
		Field string `san:"lower"`
	}
	type TestStrStructDef struct {
		Field string `san:"def=et"`
	}
	type TestStrStructTruncTrimLower struct {
		Field string `san:"max=2,trim,lower"`
	}
	type TestStrStructPtrNoOp struct {
		Field *string
	}
	type TestStrStructPtrTrunc struct {
		Field *string `san:"max=2"`
	}
	type TestStrStructPtrTrim struct {
		Field *string `san:"trim"`
	}
	type TestStrStructPtrLower struct {
		Field *string `san:"lower"`
	}
	type TestStrStructPtrDef struct {
		Field *string `san:"def=et"`
	}
	type TestStrStructPtrTruncTrimLowerDef struct {
		Field *string `san:"max=2,trim,lower,def=et"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argString0 := " tEst "
	resString0 := " tEst "
	argString1 := " tEst "
	resString1 := " t"
	argString2 := " tEst "
	resString2 := "tEst"
	argString3 := " tEst "
	resString3 := " test "
	resString4 := "et"
	argString5 := " tEst "
	resString5 := "te"

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
			name: "No operation if field does not have tags for string.",
			args: args{
				v: &TestStrStructNoOp{
					Field: " tEst ",
				},
				idx: 0,
			},
			want: &TestStrStructNoOp{
				Field: " tEst ",
			},
			wantErr: false,
		},
		{
			name: "Truncates a string field on a struct with the tag.",
			args: args{
				v: &TestStrStructTrunc{
					Field: " tEst ",
				},
				idx: 0,
			},
			want: &TestStrStructTrunc{
				Field: " t",
			},
			wantErr: false,
		},
		{
			name: "Trims a string field on a struct with the tag.",
			args: args{
				v: &TestStrStructTrim{
					Field: " tEst ",
				},
				idx: 0,
			},
			want: &TestStrStructTrim{
				Field: "tEst",
			},
			wantErr: false,
		},
		{
			name: "Lowercases a string field on a struct with the tag.",
			args: args{
				v: &TestStrStructLower{
					Field: " tEst ",
				},
				idx: 0,
			},
			want: &TestStrStructLower{
				Field: " test ",
			},
			wantErr: false,
		},
		{
			name: "Default tag has no effect on string on a struct with the tag.",
			args: args{
				v: &TestStrStructDef{
					Field: "",
				},
				idx: 0,
			},
			want: &TestStrStructDef{
				Field: "",
			},
			wantErr: false,
		},
		{
			name: "Trims, truncates, and lowercases a string field on a struct with the tag.",
			args: args{
				v: &TestStrStructTruncTrimLower{
					Field: " tEst ",
				},
				idx: 0,
			},
			want: &TestStrStructTruncTrimLower{
				Field: "te",
			},
			wantErr: false,
		},
		{
			name: "Lowercases a single char string field on a struct with the tag, without throwing an error (max tag doesn't result in mutation).",
			args: args{
				v: &TestStrStructTruncTrimLower{
					Field: "T",
				},
				idx: 0,
			},
			want: &TestStrStructTruncTrimLower{
				Field: "t",
			},
			wantErr: false,
		},
		{
			name: "No operation if field does not have tags for *string.",
			args: args{
				v: &TestStrStructPtrNoOp{
					Field: &argString0,
				},
				idx: 0,
			},
			want: &TestStrStructPtrNoOp{
				Field: &resString0,
			},
			wantErr: false,
		},
		{
			name: "Truncates a *string field on a struct with the tag.",
			args: args{
				v: &TestStrStructPtrTrunc{
					Field: &argString1, // ' tEst '
				},
				idx: 0,
			},
			want: &TestStrStructPtrTrunc{
				Field: &resString1, // ' t'
			},
			wantErr: false,
		},
		{
			name: "Trims a *string field on a struct with the tag.",
			args: args{
				v: &TestStrStructPtrTrim{
					Field: &argString2, // ' tEst '
				},
				idx: 0,
			},
			want: &TestStrStructPtrTrim{
				Field: &resString2, // 'tEst'
			},
			wantErr: false,
		},
		{
			name: "Lowercases a *string field on a struct with the tag.",
			args: args{
				v: &TestStrStructPtrLower{
					Field: &argString3, // ' tEst '
				},
				idx: 0,
			},
			want: &TestStrStructPtrLower{
				Field: &resString3, // ' test '
			},
			wantErr: false,
		},
		{
			name: "Puts a default value for a *string field that was nil on a struct with the tag.",
			args: args{
				v: &TestStrStructPtrTruncTrimLowerDef{
					Field: nil,
				},
				idx: 0,
			},
			want: &TestStrStructPtrTruncTrimLowerDef{
				Field: &resString4, // et
			},
			wantErr: false,
		},
		{
			name: "Trims, truncates, and lowercases a *string field on a struct with the tag.",
			args: args{
				v: &TestStrStructPtrTruncTrimLowerDef{
					Field: &argString5, // ' tEst '
				},
				idx: 0,
			},
			want: &TestStrStructPtrTruncTrimLowerDef{
				Field: &resString5, // te
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
