package sanitize

import (
	"reflect"
	"testing"
	"time"
)

func Test_sanitizeStrField(t *testing.T) {
	s, _ := New()

	type TestStrStructNoOp struct {
		Field string
	}
	type TestStrStructTrunc struct {
		Field string `san:"max=2"`
	}
	type TestStrStructBadTrunc struct {
		Field string `san:"max=no"`
	}
	type TestStrStructTrim struct {
		Field string `san:"trim"`
	}
	type TestStrStructTrimCustom struct {
		Field string `san:"trim= \ng7"`
	}
	type TestStrStructLower struct {
		Field string `san:"lower"`
	}
	type TestStrStructUpper struct {
		Field string `san:"upper"`
	}
	type TestStrStructTitle struct {
		Field string `san:"title"`
	}
	type TestStrStructCap struct {
		Field string `san:"cap"`
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
	type TestStrStructPtrTrimCustom struct {
		Field *string `san:"trim= \ng7"`
	}
	type TestStrStructPtrLower struct {
		Field *string `san:"lower"`
	}
	type TestStrStructPtrUpper struct {
		Field *string `san:"upper"`
	}
	type TestStrStructPtrTitle struct {
		Field *string `san:"title"`
	}
	type TestStrStructPtrCap struct {
		Field *string `san:"cap"`
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
	argString3 := " tEst TeSt test TEST "
	resString3 := " test test test test "
	resString4 := "et"
	argString5 := " tEst "
	resString5 := "te"
	argString6 := " tEst TeSt test TEST "
	resString6 := " TEST TEST TEST TEST "
	argString7 := " tEst TeSt test TEST "
	resString7 := " Test Test Test Test "
	argString8 := " tEst TeSt test TEST "
	resString8 := " Test test test test "
	argString9 := " hernández "
	resString9 := " Hernández "
	argString10 := "g7\n7g tEst  7g\n7g"
	resString10 := "tEst"

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
			name: "Returns an error when max tag is not numeric for a string field on a struct with the tag.",
			args: args{
				v: &TestStrStructBadTrunc{
					Field: " tEst ",
				},
				idx: 0,
			},
			want: &TestStrStructBadTrunc{
				Field: " tEst ",
			},
			wantErr: true,
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
			name: "Trims a string field on a struct with the custom tag.",
			args: args{
				v: &TestStrStructTrimCustom{
					Field: "g7\n7g tEst  7g\n7g",
				},
				idx: 0,
			},
			want: &TestStrStructTrimCustom{
				Field: "tEst",
			},
			wantErr: false,
		},
		{
			name: "Lowercases a string field on a struct with the tag.",
			args: args{
				v: &TestStrStructLower{
					Field: " tEst TeSt test TEST ",
				},
				idx: 0,
			},
			want: &TestStrStructLower{
				Field: " test test test test ",
			},
			wantErr: false,
		},
		{
			name: "Uppercases a string field on a struct with the tag.",
			args: args{
				v: &TestStrStructUpper{
					Field: " tEst TeSt test TEST ",
				},
				idx: 0,
			},
			want: &TestStrStructUpper{
				Field: " TEST TEST TEST TEST ",
			},
			wantErr: false,
		},
		{
			name: "Title cases a string field on a struct with the tag.",
			args: args{
				v: &TestStrStructTitle{
					Field: " tEst TeSt test TEST ",
				},
				idx: 0,
			},
			want: &TestStrStructTitle{
				Field: " Test Test Test Test ",
			},
			wantErr: false,
		},
		{
			name: "Capitalizes a string field on a struct with the tag.",
			args: args{
				v: &TestStrStructCap{
					Field: " tEst TeSt test TEST ",
				},
				idx: 0,
			},
			want: &TestStrStructCap{
				Field: " Test test test test ",
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
			name: "Trims a string field on a struct with the custom tag.",
			args: args{
				v: &TestStrStructPtrTrimCustom{
					Field: &argString10,
				},
				idx: 0,
			},
			want: &TestStrStructPtrTrimCustom{
				Field: &resString10,
			},
			wantErr: false,
		},
		{
			name: "Lowercases a *string field on a struct with the tag.",
			args: args{
				v: &TestStrStructPtrLower{
					Field: &argString3, // ' tEst TeSt test TEST '
				},
				idx: 0,
			},
			want: &TestStrStructPtrLower{
				Field: &resString3, // ' test test test test '
			},
			wantErr: false,
		},
		{
			name: "Uppercases a *string field on a struct with the tag.",
			args: args{
				v: &TestStrStructPtrUpper{
					Field: &argString6, // ' tEst TeSt test TEST '
				},
				idx: 0,
			},
			want: &TestStrStructPtrUpper{
				Field: &resString6, // ' TEST TEST TEST TEST '
			},
			wantErr: false,
		},
		{
			name: "Title cases a *string field on a struct with the tag.",
			args: args{
				v: &TestStrStructPtrTitle{
					Field: &argString7, // ' tEst TeSt test TEST '
				},
				idx: 0,
			},
			want: &TestStrStructPtrTitle{
				Field: &resString7, // ' Test Test Test Test '
			},
			wantErr: false,
		},
		{
			name: "Capitalizes a *string field on a struct with the tag.",
			args: args{
				v: &TestStrStructPtrCap{
					Field: &argString8, // ' tEst TeSt test TEST '
				},
				idx: 0,
			},
			want: &TestStrStructPtrCap{
				Field: &resString8, // ' Test test test test '
			},
			wantErr: false,
		},
		{
			name: "Title cases a *string field on a struct with the tag when the string has a character with a punctuation mark.",
			args: args{
				v: &TestStrStructPtrTitle{
					Field: &argString9,
				},
				idx: 0,
			},
			want: &TestStrStructPtrTitle{
				Field: &resString9,
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

func Test_sanitizeStrField_Slice(t *testing.T) {
	s, _ := New()

	type TestStrStructStrSli struct {
		Field []string `san:"max=2,trim,lower"`
	}
	type TestStrStructStrPtrSli struct {
		Field []*string `san:"max=2,trim,lower"`
	}
	type TestStrStructStrPtrSliDef struct {
		Field []*string `san:"max=2,trim,lower,def=hello"`
	}
	type TestStrStructStrSliPtr struct {
		Field *[]string `san:"max=2,trim,lower"`
	}
	type TestStrStructStrPtrSliPtr struct {
		Field *[]*string `san:"max=2,trim,lower"`
	}
	type TestStrStructStrPtrSliPtrDef struct {
		Field *[]*string `san:"max=2,trim,lower,def=hello"`
	}

	// Each *string test has isolated arguments and results, since the
	// arguments will be mutated, they should not be reused
	argString0 := " tEst "
	resString0 := "te"
	argString1 := " test "
	resString1 := "te"
	argString2 := " TEST "
	resString2 := "te"
	resString3 := "hello"
	argString4 := " tEst "
	resString4 := "te"
	argString5 := " test "
	resString5 := "te"
	argString6 := " TEST "
	resString6 := "te"
	resString7 := "hello"

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
			name: "Applies tags to a non-empty []string field.",
			args: args{
				v: &TestStrStructStrSli{
					Field: []string{
						" tEst ",
						" test ",
						" TEST ",
					},
				},
				idx: 0,
			},
			want: &TestStrStructStrSli{
				Field: []string{
					"te",
					"te",
					"te",
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to an empty []string field.",
			args: args{
				v:   &TestStrStructStrSli{},
				idx: 0,
			},
			want:    &TestStrStructStrSli{},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty []*string field.",
			args: args{
				v: &TestStrStructStrPtrSli{
					Field: []*string{
						&argString0,
						&argString1,
						&argString2,
					},
				},
				idx: 0,
			},
			want: &TestStrStructStrPtrSli{
				Field: []*string{
					&resString0,
					&resString1,
					&resString2,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty []*string field.",
			args: args{
				v: &TestStrStructStrPtrSli{
					Field: []*string{
						nil,
						nil,
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructStrPtrSli{
				Field: []*string{
					nil,
					nil,
					nil,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags (with default) to a non-empty []*string field.",
			args: args{
				v: &TestStrStructStrPtrSliDef{
					Field: []*string{
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructStrPtrSliDef{
				Field: []*string{
					&resString3,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]string field.",
			args: args{
				v: &TestStrStructStrSliPtr{
					Field: &[]string{
						" tEst ",
						" test ",
						" TEST ",
					},
				},
				idx: 0,
			},
			want: &TestStrStructStrSliPtr{
				Field: &[]string{
					"te",
					"te",
					"te",
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to an empty *[]string field.",
			args: args{
				v:   &TestStrStructStrSliPtr{},
				idx: 0,
			},
			want:    &TestStrStructStrSliPtr{},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]*string field.",
			args: args{
				v: &TestStrStructStrPtrSliPtr{
					Field: &[]*string{
						&argString4,
						&argString5,
						&argString6,
					},
				},
				idx: 0,
			},
			want: &TestStrStructStrPtrSliPtr{
				Field: &[]*string{
					&resString4,
					&resString5,
					&resString6,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags to a non-empty *[]*string field.",
			args: args{
				v: &TestStrStructStrPtrSliPtr{
					Field: &[]*string{
						nil,
						nil,
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructStrPtrSliPtr{
				Field: &[]*string{
					nil,
					nil,
					nil,
				},
			},
			wantErr: false,
		},
		{
			name: "Applies tags (with default) to a non-empty *[]*string field.",
			args: args{
				v: &TestStrStructStrPtrSliPtrDef{
					Field: &[]*string{
						nil,
					},
				},
				idx: 0,
			},
			want: &TestStrStructStrPtrSliPtrDef{
				Field: &[]*string{
					&resString7,
				},
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

func Test_toTitle(t *testing.T) {
	tests := []struct {
		s    string
		want string
	}{
		{
			s:    " lorem! IPSUM. doLOR, sIT& aMeT_ ",
			want: " Lorem! Ipsum. Dolor, Sit& Amet_ ",
		},
		{
			s:    "hello World",
			want: "Hello World",
		},
		{
			s:    " FOO BAR",
			want: " Foo Bar",
		},
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := toTitle(tt.s); got != tt.want {
				t.Errorf("toTitle() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_toCap(t *testing.T) {
	tests := []struct {
		s    string
		want string
	}{
		{
			s:    " lorem! IPSUM. doLOR, sIT& aMeT_ ",
			want: " Lorem! ipsum. dolor, sit& amet_ ",
		},
		{
			s:    "hello world",
			want: "Hello world",
		},
		{
			s:    " FOO BAR",
			want: " Foo bar",
		},
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := toCap(tt.s); got != tt.want {
				t.Errorf("toCap() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_xss(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want string
	}{
		{
			name: "empty string",
			s:    "",
			want: "",
		},
		{
			name: "regular string",
			s:    "this is a normal string",
			want: "this is a normal string",
		},
		{
			name: "should replace whitespace combinations with a single whitespace",
			s:    " too  many\t\nwhite   spaces ",
			want: " too many white spaces ",
		},
		{
			name: "should remove ()<>[]{} brackets and =;? symbols",
			s:    "no < > ( ) { } [ ] brackets = or ; strange ? symbols",
			want: "no brackets or strange symbols",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := xss(tt.s); got != tt.want {
				t.Errorf("xss() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_date(t *testing.T) {
	d3339 := time.Now().Format(time.RFC3339)
	d1123 := time.Now().Format(time.RFC1123)
	d850 := time.Now().Format(time.RFC850)

	type args struct {
		in         []string
		keepFormat bool
		out        string
		v          string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "invalid date",
			args: args{
				in: []string{
					time.RFC1123,
					time.RFC822,
				},
				v: "i dont think this is a date",
			},
			want: "",
		},
		{
			name: "valid date, but no input",
			args: args{
				v: d3339,
			},
			want: "",
		},
		{
			name: "valid date, but wrong input",
			args: args{
				in: []string{
					time.RFC1123,
					time.RFC822,
				},
				v: d3339,
			},
			want: "",
		},
		{
			name: "format recognized and replaced (1st format)",
			args: args{
				in: []string{
					time.RFC1123,
					time.RFC822,
					time.RFC850,
				},
				out: time.RFC3339,
				v:   d1123,
			},
			want: d3339,
		},
		{
			name: "format recognized and replaced (3rd format)",
			args: args{
				in: []string{
					time.RFC1123,
					time.RFC822,
					time.RFC850,
				},
				out: time.RFC3339,
				v:   d850,
			},
			want: d3339,
		},
		{
			name: "format recognized but not replaced (1st format)",
			args: args{
				in: []string{
					time.RFC1123,
					time.RFC822,
					time.RFC850,
				},
				keepFormat: true,
				out:        time.RFC3339,
				v:          d1123,
			},
			want: d1123,
		},
		{
			name: "format recognized but not replaced (3rd format)",
			args: args{
				in: []string{
					time.RFC1123,
					time.RFC822,
					time.RFC850,
				},
				keepFormat: true,
				out:        time.RFC3339,
				v:          d850,
			},
			want: d850,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := date(tt.args.in, tt.args.keepFormat, tt.args.out, tt.args.v); got != tt.want {
				t.Errorf("date() = %v, want %v", got, tt.want)
			}
		})
	}
}
