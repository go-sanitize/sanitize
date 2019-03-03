package sanitize

import (
	"testing"
)

func Test_parseInt(t *testing.T) {
	tests := []struct {
		name    string
		want    int
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
			got, err := parseInt(tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseInt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseInt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseInt8(t *testing.T) {
	tests := []struct {
		name    string
		want    int8
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
			name:    "-100",
			want:    -100,
			wantErr: false,
		},
		{
			name:    "100",
			want:    100,
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
			got, err := parseInt8(tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseInt8() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseInt8() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseInt16(t *testing.T) {
	tests := []struct {
		name    string
		want    int16
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
			name:    "-10000",
			want:    -10000,
			wantErr: false,
		},
		{
			name:    "10000",
			want:    10000,
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
			got, err := parseInt16(tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseInt16() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseInt16() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseInt32(t *testing.T) {
	tests := []struct {
		name    string
		want    int32
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
			got, err := parseInt32(tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseInt32() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseInt32() = %v, want %v", got, tt.want)
			}
		})
	}
}

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

func Test_parseUint(t *testing.T) {
	tests := []struct {
		name    string
		want    uint
		wantErr bool
	}{
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
			got, err := parseUint(tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseUint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseUint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseUint8(t *testing.T) {
	tests := []struct {
		name    string
		want    uint8
		wantErr bool
	}{
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
			name:    "100",
			want:    100,
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
			got, err := parseUint8(tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseUint8() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseUint8() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseUint16(t *testing.T) {
	tests := []struct {
		name    string
		want    uint16
		wantErr bool
	}{
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
			name:    "10000",
			want:    10000,
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
			got, err := parseUint16(tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseUint16() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseUint16() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseUint32(t *testing.T) {
	tests := []struct {
		name    string
		want    uint32
		wantErr bool
	}{
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
			got, err := parseUint32(tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseUint32() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseUint32() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseUint64(t *testing.T) {
	tests := []struct {
		name    string
		want    uint64
		wantErr bool
	}{
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
			got, err := parseUint64(tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseUint64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseUint64() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseFloat32(t *testing.T) {
	tests := []struct {
		name    string
		want    float32
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
			got, err := parseFloat32(tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseFloat32() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseFloat32() = %v, want %v", got, tt.want)
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
