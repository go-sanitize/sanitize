# sanitize

Sanitizes structs by mutating them according to rules in `san` tags.

Usage example:

```go
type Dog struct {
	Name  string  `san:"max=5,trim,lower"`
	Breed *string `san:"def=unknown"`
}

d := Dog{
    Name: "Borky Borkins",
    Breed: nil,
}

sanitize.Struct(&d)

fmt.Printf("Name: %s, Breed: %s", d.Name, d.Breed) // Name: borky, Breed: unknown
```
