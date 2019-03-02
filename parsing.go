package sanitize

import (
	"strconv"
)

func parseInt64(str string) (int64, error) {
	return strconv.ParseInt(str, 10, 64)
}

func parseFloat64(str string) (float64, error) {
	return strconv.ParseFloat(str, 64)
}
