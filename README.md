# sanitize

[![Go](https://github.com/go-sanitize/sanitize/actions/workflows/go.yml/badge.svg)](https://github.com/go-sanitize/sanitize/actions/workflows/go.yml)

Package sanitize provides an easy way to clean fields in structs: trimming, applying maximum string lengths, minimum numeric values, default values, and so on...

Sanitizing a struct will mutate the fields according to rules in the `san` tag. The tags work for both pointers and basic types.


## Install

`go get github.com/go-sanitize/sanitize`


## Example

```go
package main

import (
	"fmt"

	"github.com/go-sanitize/sanitize"
)

type Dog struct {
	Name  string  `san:"max=5,trim,lower"`
	Breed *string `san:"def=unknown"`
}

func main() {
	dog := Dog{
		Name:  "Borky Borkins",
		Breed: nil,
	}
	fmt.Printf("Raw data -> %+v\n", dog)

	s, _ := sanitize.New()
	s.Sanitize(&dog)
	fmt.Printf("Sanitized data -> Name: %s, Breed: %s\n", dog.Name, *dog.Breed)
}
```

Output:

```
Raw data -> {Name:Borky Borkins Breed:<nil>}
Sanitized data -> Name: borky, Breed: unknown
```

## Available options

### Tag Name

Default: `san`

Use this option to tell the sanitizer to use another tag name instead of "san".

```go
s := sanitizer.New(sanitizer.OptionTagName{
    Value: "mytag",
})
```

### Date Format

Default: `Input = []`, `Output = ""`, and `KeepFormat = false`.

Use this option to specify which date format we should use.

The `Input` field tells us which date formats we can accept (such as RFC3339 and RFC3339Nano).

The `KeepFormat` field tells us if we should keep the date format unchanged, or if we want to force them into another format.

The `Output` field tells us which format we should use for the output if `KeepFormat` is set to false.

If a date can not be parsed by the formats specified in the `Input` field, the field will be converted into an empty string.

Example:
- If `Input = [RFC1123, RFC3339Nano]`, `KeepFormat: false`, and `Output = RFC3339`, we will accept dates in the RFC1123 and RFC3339Nano formats and convert them to RFC3339 format. Any other formats will be converted into an empty string.
- If `Input = [RFC1123, RFC3339Nano]` and `KeepFormat: true`, we will accept dates in the RFC1123 and RFC3339Nano formats and keep them in the same format. Any other formats will be converted into an empty string.
- If `Input = []`, the field will be converted into an empty string, since there are no allowed input formats.

```go
s := sanitizer.New(sanitizer.OptionDateFormat{
    Input: []string{
        time.RFC3339,
        time.RFC3339Nano,
    },
    KeepFormat: false,
    Output:     time.RFC1123,
})
```

### Custom Sanitizers

Use this option to register a custom sanitizer function. The sanitizer function is responsible for determining if the field's type is supported for that sanitizer.

The `Name` field tells us what tag name corresponds to the sanitizer.

The `Sanitizer` field tells us which sanitizer function to call when this tag is used. All sanitizers must have this signature: `func(s Sanitizer, structValue reflect.Value, idx int) error`.

```go
// exclaim adds punctuated enthusiasm to a string.
func exclaim(s Sanitizer, structValue reflect.Value, idx int) error {
    fieldValue := structValue.Field(idx)
    if fieldValue.Kind() == reflect.Ptr && !fieldValue.IsNil() {
        fieldValue = fieldValue.Elem()
    }

    if fieldValue.Kind() != reflect.String {
        return fmt.Errorf("exclaim: invalid type %q", fieldValue.Kind().String())
    }

    v := fieldValue.Interface().(string)
    if strings.HasSuffix(v, "...") {
        v = v[:len(v)-3] + "!"
    } else if strings.HasSuffix(v, ".") {
        v = v[:len(v)-1] + "!"
    } else {
        v += "!"
    }

    fieldValue.SetString(v)

    return nil
}

type BlogPost struct {
    Title    string `san:"title"`
    Byline   string `san:"cap,exclaim"`
    Contents []byte
}

func main() {
    bp := BlogPost{
        Title:  "sanitizing go structs"
        Byline: "clean up you structs"
    }

    s := sanitizer.New(
        sanitizer.OptionSanitizerFunc{
            Name:      "exclaim",
            Sanitizer: exclaim,
        },
    )
    s.Sanitize(&bp)

    fmt.Printf("Title:%q Byline:%q", bp.Title, bp.Byline)
    // Title: "Sanitizing Go Structs" Byline:"Clean up your structs!"
}
```

## Available tags

### string

1. **max=`<n>`** - Maximum string length. It will truncate the string to `<n>` characters if this limit is exceeded
1. **trim** - Remove trailing spaces left and right
1. **trim=`<c>`** - Remove trailing characters `<c>` left and right. You can provide more than one character. Example: `trim= \n` will trim spaces and new lines
1. **lower** - Lowercase all characters in the string
1. **upper** - Uppercase all characters in the string
1. **title** - First character of every word is changed to uppercase, the rest to lowercase. Uses Go's built in `strings.Title()` function.
1. **cap** - Only the first letter of the string will be changed to uppercase, the rest to lowercase
1. **def=`<n>`** (only available for pointers) - Sets a default `<n>` value in case the pointer is `nil`
1. **xss** - Will remove brackets such as <>[](){} and the characters !=? from the string
1. **date** - Will parse the string using the input formats provided in the options and print it using the output format provided in the options. If the string can not be parsed, it will be left empty

The order of precedence will be: **xss** -> **trim** -> **date** -> **max** -> **lower** -> **upper** -> **title** -> **cap**


### int, uint, and float

Available for: *int*, *int8*, *int16*, *int32*, *int64*, *uint*, *uint8*, *uint16*, *uint32*, *uint64*, *float32*, and *float64*

1. **max=`<n>`** - Highest value allowed. If the limit is exceeded, the value will be set to `<n>`
1. **min=`<n>`** - Lowest value allowed. If the limit is exceeded, the value will be set to `<n>`
1. **def=`<n>`** (only available for pointers) - Sets a default `<n>` value in case the pointer is `nil`


### bool

1. **def=`<n>`** (only available for pointers) - Sets a default `<n>` value in case the pointer is `nil`


### slices

1. **maxsize=`<n>`** - Maximum slice length. It will truncate the slice to `<n>` elements if the limit is exceeded

Other tags will be applied for every element in the slice, not the slice itself. For example: a field of type `[]string` with the tag `max=5` will have every string truncated to 5 characters at most.
