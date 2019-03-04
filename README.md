# sanitize

[![CircleCI](https://circleci.com/gh/go-sanitize/sanitize/tree/master.svg?style=svg)](https://circleci.com/gh/go-sanitize/sanitize/tree/master)

Package sanitize provides an easy way to clean fields in structs: trimming, applying maximum string lengths, minimum numeric values, default values, and so on...

Sanitizing a struct will mutate the fields according to rules in the `san` tag. The tags work for both pointers and basic types.


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

### string

1. **max=`<n>`** - Maximum string length. It will truncate the string to `<n>` characters if this limit is exceeded
1. **trim** - Remove trailing spaces left and right
1. **lower** - Lowercase all characters in the string
1. **upper** - Uppercase all characters in the string
1. **title** - First character of every word is changed to uppercase, the rest to lowercase
1. **cap** - Only the first letter of the string will be changed to uppercase, the rest to lowercase
1. **def=`<n>`** (only available for pointers) - Sets a default `<n>` value in case the pointer is `nil`

The order of precedence will be: **trim** -> **max** -> **lower**


### int, uint, and float

Available for: *int*, *int8*, *int16*, *int32*, *int64*, *uint*, *uint8*, *uint16*, *uint32*, *uint64*, *float32*, and *float64*

1. **max=`<n>`** - Highest value allowed. If the limit is exceeded, the value will be set to `<n>`
1. **min=`<n>`** - Lowest value allowed. If the limit is exceeded, the value will be set to `<n>`
1. **def=`<n>`** (only available for pointers) - Sets a default `<n>` value in case the pointer is `nil`


### bool

1. **def=`<n>`** (only available for pointers) - Sets a default `<n>` value in case the pointer is `nil`


### slices

Tags will be applied for every element in the slice, not the slice itself. For example: a field of type `[]string` with the tag `max=5` will have every string truncated to 5 characters at most.
