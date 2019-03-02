package sanitize

import (
	"fmt"
	"testing"
)

func Test(t *testing.T) {
	type Dog struct {
		Name  string  `san:"max=5,trim,lower"`
		Breed *string `san:"def=unknown"`
	}

	d := Dog{
		Name:  "Borky Borkins",
		Breed: nil,
	}

	s, _ := New()
	s.Sanitize(&d)
	fmt.Println(d)
}
