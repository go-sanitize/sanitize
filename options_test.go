package sanitize

import (
	"reflect"
	"testing"
)

type unknownOption struct{}

var _ Option = unknownOption{}

func (o unknownOption) id() string {
	return "strangetag!"
}

func (o unknownOption) value() interface{} {
	return "very strange indeed"
}

func Test_New(t *testing.T) {
	type args struct {
		options []Option
	}
	tests := []struct {
		name    string
		args    args
		want    *Sanitizer
		wantErr bool
	}{
		{
			name: "no options",
			args: args{
				options: []Option{},
			},
			want: &Sanitizer{
				tagName: DefaultTagName,
			},
			wantErr: false,
		},
		{
			name: "unknown option",
			args: args{
				options: []Option{
					unknownOption{},
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "valid tag name option",
			args: args{
				options: []Option{
					OptionTagName{Value: "mytag"},
				},
			},
			want: &Sanitizer{
				tagName: "mytag",
			},
			wantErr: false,
		},
		{
			name: "invalid tag name option (too short)",
			args: args{
				options: []Option{
					OptionTagName{Value: ""},
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "invalid tag name option (too big)",
			args: args{
				options: []Option{
					OptionTagName{Value: "thistagiswaytoolarge"},
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "unknown tag",
			args: args{
				options: []Option{
					OptionTagName{Value: "thistagiswaytoolarge"},
				},
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.options...)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}
