package sanitize

import (
	"reflect"
	"testing"
)

func Test_sanitizeSliceField(t *testing.T) {
	s, _ := New()

	type TestSliceStr struct {
		Field []string `san:"maxsize=2"`
	}
	type TestSliceStrPtr struct {
		Field []*string `san:"maxsize=2"`
	}
	type TestSlicePtrStr struct {
		Field *[]string `san:"maxsize=2"`
	}
	type TestSlicePtrStrPtr struct {
		Field *[]*string `san:"maxsize=2"`
	}

	sampleString1 := "test1"
	sampleString2 := "test2"
	sampleString3 := "test3"

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
			name: "Skip trim slice of strings",
			args: args{
				v: &TestSliceStr{
					Field: []string{
						sampleString1,
					},
				},
				idx: 0,
			},
			want: &TestSliceStr{
				Field: []string{
					sampleString1,
				},
			},
			wantErr: false,
		},
		{
			name: "Trim slice of strings",
			args: args{
				v: &TestSliceStr{
					Field: []string{
						sampleString1,
						sampleString2,
						sampleString3,
					},
				},
				idx: 0,
			},
			want: &TestSliceStr{
				Field: []string{
					sampleString1,
					sampleString2,
				},
			},
			wantErr: false,
		},
		{
			name: "Trim slice of string pointers",
			args: args{
				v: &TestSliceStrPtr{
					Field: []*string{
						&sampleString1,
						&sampleString2,
						&sampleString3,
					},
				},
				idx: 0,
			},
			want: &TestSliceStrPtr{
				Field: []*string{
					&sampleString1,
					&sampleString2,
				},
			},
			wantErr: false,
		},
		{
			name: "Trim slice pointer of strings",
			args: args{
				v: &TestSlicePtrStr{
					Field: &[]string{
						sampleString1,
						sampleString2,
						sampleString3,
					},
				},
				idx: 0,
			},
			want: &TestSlicePtrStr{
				Field: &[]string{
					sampleString1,
					sampleString2,
				},
			},
			wantErr: false,
		},
		{
			name: "Trim slice pointer of string pointers",
			args: args{
				v: &TestSlicePtrStrPtr{
					Field: &[]*string{
						&sampleString1,
						&sampleString2,
						&sampleString3,
					},
				},
				idx: 0,
			},
			want: &TestSlicePtrStrPtr{
				Field: &[]*string{
					&sampleString1,
					&sampleString2,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sanitizeSliceField(*s, reflect.ValueOf(tt.args.v).Elem(), tt.args.idx); (err != nil) != tt.wantErr {
				t.Errorf("sanitizeSliceField() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("sanitizeSliceField() - failed field - got %+v but wanted %+v", tt.args.v, tt.want)
			}
		})
	}
}

