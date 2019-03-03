package sanitize

import (
	"strconv"
)

func parseInt(str string) (int, error) {
	v, err := strconv.ParseInt(str, 10, 64)
	return int(v), err
}

func parseInt8(str string) (int8, error) {
	v, err := strconv.ParseInt(str, 10, 8)
	return int8(v), err
}

func parseInt16(str string) (int16, error) {
	v, err := strconv.ParseInt(str, 10, 16)
	return int16(v), err
}

func parseInt32(str string) (int32, error) {
	v, err := strconv.ParseInt(str, 10, 32)
	return int32(v), err
}

func parseInt64(str string) (int64, error) {
	return strconv.ParseInt(str, 10, 64)
}

func parseUint(str string) (uint, error) {
	v, err := strconv.ParseUint(str, 10, 64)
	return uint(v), err
}

func parseUint8(str string) (uint8, error) {
	v, err := strconv.ParseUint(str, 10, 8)
	return uint8(v), err
}

func parseUint16(str string) (uint16, error) {
	v, err := strconv.ParseUint(str, 10, 16)
	return uint16(v), err
}

func parseUint32(str string) (uint32, error) {
	v, err := strconv.ParseUint(str, 10, 32)
	return uint32(v), err
}

func parseUint64(str string) (uint64, error) {
	return strconv.ParseUint(str, 10, 64)
}

func parseFloat32(str string) (float32, error) {
	v, err := strconv.ParseFloat(str, 32)
	return float32(v), err
}

func parseFloat64(str string) (float64, error) {
	return strconv.ParseFloat(str, 64)
}
