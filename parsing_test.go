package sanitize

import (
	"testing"
)

func Test_parseInt64(t *testing.T) {
	tests := []struct {
		name    string
		want    int64
		wantErr bool
	}{
		{
			name:    "-1",
			want:    -1,
			wantErr: false,
		},
		{
			name:    "1",
			want:    1,
			wantErr: false,
		},
		{
			name:    "0",
			want:    0,
			wantErr: false,
		},
		{
			name:    "-1.64852167",
			want:    0,
			wantErr: true,
		},
		{
			name:    "1.64852167",
			want:    0,
			wantErr: true,
		},
		{
			name:    "0.64852167",
			want:    0,
			wantErr: true,
		},
		{
			name:    "-100000",
			want:    -100000,
			wantErr: false,
		},
		{
			name:    "100000",
			want:    100000,
			wantErr: false,
		},
		{
			name:    "??",
			want:    0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseInt64(tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseInt64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseInt64() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseFloat64(t *testing.T) {
	tests := []struct {
		name    string
		want    float64
		wantErr bool
	}{
		{
			name:    "-1",
			want:    -1,
			wantErr: false,
		},
		{
			name:    "1",
			want:    1,
			wantErr: false,
		},
		{
			name:    "0",
			want:    0,
			wantErr: false,
		},
		{
			name:    "-1.64852167",
			want:    -1.64852167,
			wantErr: false,
		},
		{
			name:    "1.64852167",
			want:    1.64852167,
			wantErr: false,
		},
		{
			name:    "0.64852167",
			want:    0.64852167,
			wantErr: false,
		},
		{
			name:    "-100000",
			want:    -100000,
			wantErr: false,
		},
		{
			name:    "100000",
			want:    100000,
			wantErr: false,
		},
		{
			name:    "??",
			want:    0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFloat64(tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseFloat64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseFloat64() = %v, want %v", got, tt.want)
			}
		})
	}
}
