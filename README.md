# sanitize

Package sanitize provides an easy way to clean fields in structs: trimming, applying maximum string lengths, minimum numeric values, default values, and so on...

Sanitizing a struct will mutate the fields according to rules in the `san` tag. The tags work for both pointers and primitive values.


## Install

`go get github.com/go-sanitize/sanitize`


## Usage example

```go
package main

import "github.com/go-sanitize/sanitize"

type Dog struct {
    Name  string  `san:"max=5,trim,lower"`
    Breed *string `san:"def=unknown"`
}

func main() {
    d := Dog{
        Name: "Borky Borkins",
        Breed: nil,
    }

    s := sanitizer.New()
    s.Sanitize(&d)

    fmt.Printf("Name: %s, Breed: %s", d.Name, d.Breed)
    // Name: borky, Breed: unknown
}
```

## Available tags

### String

1. *max=`<n>`* - Maximum string length. It will crop the string to `<n>` characters if this limit is exceeded
1. *trim* - Remove trailing spaces left and right
1. *lower* - Lowercase all characters in the string
1. *def=`<n>`* (only available for pointers) - Sets a default `<n>` value in case the pointer is `nil`

The order of precedence will be: **trim** -> **max** -> **lower**


### Int64, Float64

1. *max=`<n>`* - Highest value allowed. If the limit is exceeded, the value will be set to `<n>`
1. *min=`<n>`* - Lowest value allowed. If the limit is exceeded, the value will be set to `<n>`
1. *def=`<n>`* (only available for pointers) - Sets a default `<n>` value in case the pointer is `nil`


### Bool

1. *def=`<n>`* (only available for pointers) - Sets a default `<n>` value in case the pointer is `nil`
