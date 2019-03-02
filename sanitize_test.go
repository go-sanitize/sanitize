package sanitize

import (
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

func Test_Sanitize(t *testing.T) {
	s, _ := New()
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
			if err := s.Sanitize(tt.args.s); (err != nil) != tt.wantErr {
				t.Errorf("Sanitize() error = %v, wantErr %v", err, tt.wantErr)
			}
			tt.postTestFn()
		})
	}
}
