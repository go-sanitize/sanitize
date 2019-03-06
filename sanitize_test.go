package sanitize

import (
	"reflect"
	"testing"
	"time"
)

func Test_Sanitize_CodeSample(t *testing.T) {
	type Dog struct {
		Name  string  `san:"max=5,trim,lower"`
		Breed *string `san:"def=unknown"`
	}

	d := Dog{
		Name:  "Borky Borkins",
		Breed: nil,
	}

	unknown := "unknown"
	expected := Dog{
		Name:  "borky",
		Breed: &unknown,
	}

	s, _ := New()
	s.Sanitize(&d)

	if !reflect.DeepEqual(d, expected) {
		gotBreed := "<nil>"
		if d.Breed != nil {
			gotBreed = *d.Breed
		}
		expectedBreed := "<nil>"
		if expected.Breed != nil {
			expectedBreed = *expected.Breed
		}
		t.Errorf(
			"Sanitize() - got { Name: %s, Breed: %s } but wanted { Name: %s, Breed: %s }",
			d.Name,
			gotBreed,
			expected.Name,
			expectedBreed,
		)
	}
}

func Test_Sanitize_Options(t *testing.T) {
	type Dog struct {
		Name            string `abcde:"max=5,trim,lower"`
		Birthday        string `abcde:"date"`
		PersonalWebsite string `abcde:"xss,trim"`
	}

	now := time.Now()

	d := Dog{
		Name:            "Borky Borkins",
		Birthday:        now.Format(time.RFC3339),
		PersonalWebsite: "<html>[head]1=1?;{/head}(/html)",
	}

	expected := Dog{
		Name:            "borky",
		Birthday:        now.Format(time.RFC850),
		PersonalWebsite: "html head 1 1 /head /html",
	}

	s, _ := New(
		OptionTagName{Value: "abcde"},
		OptionDateFormat{
			Input:  []string{time.RFC3339},
			Output: time.RFC850,
		},
	)
	s.Sanitize(&d)

	if !reflect.DeepEqual(d, expected) {
		t.Errorf("Sanitize() - got %+v but wanted %+v", d, expected)
	}
}

func Test_Sanitize(t *testing.T) {

	type TestStruct struct {
		StrField           string     `san:"max=2,trim,lower"`
		IntField           int        `san:"min=11,max=12"`
		Int8Field          int8       `san:"min=21,max=22"`
		Int16Field         int16      `san:"min=31,max=32"`
		Int32Field         int32      `san:"min=41,max=42"`
		Int64Field         int64      `san:"min=51,max=52"`
		UintField          uint       `san:"min=61,max=62"`
		Uint8Field         uint8      `san:"min=71,max=72"`
		Uint16Field        uint16     `san:"min=81,max=82"`
		Uint32Field        uint32     `san:"min=91,max=92"`
		Uint64Field        uint64     `san:"min=101,max=102"`
		Float32Field       float32    `san:"max=22.3,min=22.2"`
		Float64Field       float64    `san:"max=42.3,min=42.2"`
		SlcStrField        []string   `san:"max=2,trim,lower"`
		SlcIntField        []int      `san:"min=11,max=12"`
		SlcInt8Field       []int8     `san:"min=21,max=22"`
		SlcInt16Field      []int16    `san:"min=31,max=32"`
		SlcInt32Field      []int32    `san:"min=41,max=42"`
		SlcInt64Field      []int64    `san:"min=51,max=52"`
		SlcUintField       []uint     `san:"min=61,max=62"`
		SlcUint8Field      []uint8    `san:"min=71,max=72"`
		SlcUint16Field     []uint16   `san:"min=81,max=82"`
		SlcUint32Field     []uint32   `san:"min=91,max=92"`
		SlcUint64Field     []uint64   `san:"min=101,max=102"`
		SlcFloat32Field    []float32  `san:"max=22.3,min=22.2"`
		SlcFloat64Field    []float64  `san:"max=42.3,min=42.2"`
		SlcPtrStrField     *[]string  `san:"max=2,trim,lower"`
		SlcPtrIntField     *[]int     `san:"min=11,max=12"`
		SlcPtrInt8Field    *[]int8    `san:"min=21,max=22"`
		SlcPtrInt16Field   *[]int16   `san:"min=31,max=32"`
		SlcPtrInt32Field   *[]int32   `san:"min=41,max=42"`
		SlcPtrInt64Field   *[]int64   `san:"min=51,max=52"`
		SlcPtrUintField    *[]uint    `san:"min=61,max=62"`
		SlcPtrUint8Field   *[]uint8   `san:"min=71,max=72"`
		SlcPtrUint16Field  *[]uint16  `san:"min=81,max=82"`
		SlcPtrUint32Field  *[]uint32  `san:"min=91,max=92"`
		SlcPtrUint64Field  *[]uint64  `san:"min=101,max=102"`
		SlcPtrFloat32Field *[]float32 `san:"max=22.3,min=22.2"`
		SlcPtrFloat64Field *[]float64 `san:"max=42.3,min=42.2"`
	}

	type TestStructPtr struct {
		StrField           *string     `san:"max=2,trim,lower"`
		IntField           *int        `san:"min=11,max=12"`
		Int8Field          *int8       `san:"min=21,max=22"`
		Int16Field         *int16      `san:"min=31,max=32"`
		Int32Field         *int32      `san:"min=41,max=42"`
		Int64Field         *int64      `san:"min=51,max=52"`
		UintField          *uint       `san:"min=61,max=62"`
		Uint8Field         *uint8      `san:"min=71,max=72"`
		Uint16Field        *uint16     `san:"min=81,max=82"`
		Uint32Field        *uint32     `san:"min=91,max=92"`
		Uint64Field        *uint64     `san:"min=101,max=102"`
		Float32Field       *float32    `san:"max=22.3,min=22.2"`
		Float64Field       *float64    `san:"max=42.3,min=42.2"`
		SlcStrField        []*string   `san:"max=2,trim,lower"`
		SlcIntField        []*int      `san:"min=11,max=12"`
		SlcInt8Field       []*int8     `san:"min=21,max=22"`
		SlcInt16Field      []*int16    `san:"min=31,max=32"`
		SlcInt32Field      []*int32    `san:"min=41,max=42"`
		SlcInt64Field      []*int64    `san:"min=51,max=52"`
		SlcUintField       []*uint     `san:"min=61,max=62"`
		SlcUint8Field      []*uint8    `san:"min=71,max=72"`
		SlcUint16Field     []*uint16   `san:"min=81,max=82"`
		SlcUint32Field     []*uint32   `san:"min=91,max=92"`
		SlcUint64Field     []*uint64   `san:"min=101,max=102"`
		SlcFloat32Field    []*float32  `san:"max=22.3,min=22.2"`
		SlcFloat64Field    []*float64  `san:"max=42.3,min=42.2"`
		SlcPtrStrField     *[]*string  `san:"max=2,trim,lower"`
		SlcPtrIntField     *[]*int     `san:"min=11,max=12"`
		SlcPtrInt8Field    *[]*int8    `san:"min=21,max=22"`
		SlcPtrInt16Field   *[]*int16   `san:"min=31,max=32"`
		SlcPtrInt32Field   *[]*int32   `san:"min=41,max=42"`
		SlcPtrInt64Field   *[]*int64   `san:"min=51,max=52"`
		SlcPtrUintField    *[]*uint    `san:"min=61,max=62"`
		SlcPtrUint8Field   *[]*uint8   `san:"min=71,max=72"`
		SlcPtrUint16Field  *[]*uint16  `san:"min=81,max=82"`
		SlcPtrUint32Field  *[]*uint32  `san:"min=91,max=92"`
		SlcPtrUint64Field  *[]*uint64  `san:"min=101,max=102"`
		SlcPtrFloat32Field *[]*float32 `san:"max=22.3,min=22.2"`
		SlcPtrFloat64Field *[]*float64 `san:"max=42.3,min=42.2"`
	}

	type TestStructMixedRecursiveSub struct {
		StrField    string  `san:"max=2,trim,lower"`
		StrPtrField *string `san:"max=2,trim,lower"`
	}

	type TestStructMixedRecursive struct {
		StrField      string  `san:"max=2,trim,lower"`
		StrPtrField   *string `san:"max=2,trim,lower"`
		Sub1          TestStructMixedRecursiveSub
		SubPtr1       *TestStructMixedRecursiveSub
		SliSub1       []TestStructMixedRecursiveSub
		SliPtrSubPtr1 *[]*TestStructMixedRecursiveSub
		Sub2          TestStruct
		SubPtr2       *TestStructPtr
		SubPtr3       *TestStructPtr
	}

	type TestBadStruct struct {
		Int64Field int64 `san:"min=42,max=41"`
	}

	type TestBadNestedStruct struct {
		Sub TestBadStruct
	}

	s, _ := New()

	arg1 := " PTRTEST "
	res1 := "pt"
	arg2 := " subptrtest1 "
	res2 := "su"
	arg3 := " subptrtest2 "
	res3 := "su"
	arg4 := "world"
	res4 := "wo"
	arg5 := int(10)
	res5 := int(11)
	arg6 := int8(11)
	res6 := int8(21)
	arg7 := int16(11)
	res7 := int16(31)
	arg8 := int32(11)
	res8 := int32(41)
	arg9 := int64(11)
	res9 := int64(51)
	arg10 := uint(10)
	res10 := uint(61)
	arg11 := uint8(11)
	res11 := uint8(71)
	arg12 := uint16(11)
	res12 := uint16(81)
	arg13 := uint32(11)
	res13 := uint32(91)
	arg14 := uint64(11)
	res14 := uint64(101)
	arg15 := float32(90.2)
	res15 := float32(22.3)
	arg16 := 90.2
	res16 := 42.3
	arg17 := "hello"
	res17 := "he"
	arg18 := "world"
	res18 := "wo"
	arg19 := int(1)
	res19 := int(11)
	arg20 := int(999)
	res20 := int(12)
	arg21 := int8(1)
	res21 := int8(21)
	arg22 := int8(99)
	res22 := int8(22)
	arg23 := int16(1)
	res23 := int16(31)
	arg24 := int16(999)
	res24 := int16(32)
	arg25 := int32(1)
	res25 := int32(41)
	arg26 := int32(999)
	res26 := int32(42)
	arg27 := int64(1)
	res27 := int64(51)
	arg28 := int64(999)
	res28 := int64(52)
	arg29 := uint(1)
	res29 := uint(61)
	arg30 := uint(999)
	res30 := uint(62)
	arg31 := uint8(1)
	res31 := uint8(71)
	arg32 := uint8(99)
	res32 := uint8(72)
	arg33 := uint16(1)
	res33 := uint16(81)
	arg34 := uint16(999)
	res34 := uint16(82)
	arg35 := uint32(1)
	res35 := uint32(91)
	arg36 := uint32(999)
	res36 := uint32(92)
	arg37 := uint64(1)
	res37 := uint64(101)
	arg38 := uint64(999)
	res38 := uint64(102)
	arg39 := float32(80.1)
	res39 := float32(22.3)
	arg40 := float32(10.1)
	res40 := float32(22.2)
	arg41 := float64(80.1)
	res41 := float64(42.3)
	arg42 := float64(10.1)
	res42 := float64(42.2)
	arg43 := "hello"
	res43 := "he"
	arg44 := "world"
	res44 := "wo"
	arg45 := int(1)
	res45 := int(11)
	arg46 := int(999)
	res46 := int(12)
	arg47 := int8(1)
	res47 := int8(21)
	arg48 := int8(99)
	res48 := int8(22)
	arg49 := int16(1)
	res49 := int16(31)
	arg50 := int16(999)
	res50 := int16(32)
	arg51 := int32(1)
	res51 := int32(41)
	arg52 := int32(999)
	res52 := int32(42)
	arg53 := int64(1)
	res53 := int64(51)
	arg54 := int64(999)
	res54 := int64(52)
	arg55 := uint(1)
	res55 := uint(61)
	arg56 := uint(999)
	res56 := uint(62)
	arg57 := uint8(1)
	res57 := uint8(71)
	arg58 := uint8(99)
	res58 := uint8(72)
	arg59 := uint16(1)
	res59 := uint16(81)
	arg60 := uint16(999)
	res60 := uint16(82)
	arg61 := uint32(1)
	res61 := uint32(91)
	arg62 := uint32(999)
	res62 := uint32(92)
	arg63 := uint64(1)
	res63 := uint64(101)
	arg64 := uint64(999)
	res64 := uint64(102)
	arg65 := float32(80.1)
	res65 := float32(22.3)
	arg66 := float32(10.1)
	res66 := float32(22.2)
	arg67 := float64(80.1)
	res67 := float64(42.3)
	arg68 := float64(10.1)
	res68 := float64(42.2)
	arg69 := " PTRTEST "
	res69 := "pt"
	arg70 := " subptrtest1 "
	res70 := "su"
	arg71 := " PTRTEST "
	res71 := "pt"
	arg72 := " subptrtest1 "
	res72 := "su"

	type args struct {
		s interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		want    interface{}
	}{
		{
			name: "Sanitizes a struct that contains all types of fields.",
			args: args{
				s: &TestStructMixedRecursive{
					StrField:    " TEST ",
					StrPtrField: &arg1,
					Sub1: TestStructMixedRecursiveSub{
						StrField:    " subtest1 ",
						StrPtrField: &arg2,
					},
					SubPtr1: &TestStructMixedRecursiveSub{
						StrField:    " subtest2 ",
						StrPtrField: &arg3,
					},
					SliSub1: []TestStructMixedRecursiveSub{
						{
							StrField:    " subtest1 ",
							StrPtrField: &arg69,
						},
						{
							StrField:    " subtest2 ",
							StrPtrField: &arg70,
						},
					},
					SliPtrSubPtr1: &[]*TestStructMixedRecursiveSub{
						&TestStructMixedRecursiveSub{
							StrField:    " subtest1 ",
							StrPtrField: &arg71,
						},
						&TestStructMixedRecursiveSub{
							StrField:    " subtest2 ",
							StrPtrField: &arg72,
						},
					},
					Sub2: TestStruct{
						StrField:           "hello",
						IntField:           1,
						Int8Field:          1,
						Int16Field:         1,
						Int32Field:         1,
						Int64Field:         1,
						UintField:          1,
						Uint8Field:         1,
						Uint16Field:        1,
						Uint32Field:        1,
						Uint64Field:        1,
						Float32Field:       80.1,
						Float64Field:       80.1,
						SlcStrField:        []string{"hello", "world"},
						SlcIntField:        []int{1, 999},
						SlcInt8Field:       []int8{1, 99},
						SlcInt16Field:      []int16{1, 999},
						SlcInt32Field:      []int32{1, 999},
						SlcInt64Field:      []int64{1, 999},
						SlcUintField:       []uint{1, 999},
						SlcUint8Field:      []uint8{1, 99},
						SlcUint16Field:     []uint16{1, 999},
						SlcUint32Field:     []uint32{1, 999},
						SlcUint64Field:     []uint64{1, 999},
						SlcFloat32Field:    []float32{80.1, 10.1},
						SlcFloat64Field:    []float64{80.1, 10.1},
						SlcPtrStrField:     &[]string{"hello", "world"},
						SlcPtrIntField:     &[]int{1, 999},
						SlcPtrInt8Field:    &[]int8{1, 99},
						SlcPtrInt16Field:   &[]int16{1, 999},
						SlcPtrInt32Field:   &[]int32{1, 999},
						SlcPtrInt64Field:   &[]int64{1, 999},
						SlcPtrUintField:    &[]uint{1, 999},
						SlcPtrUint8Field:   &[]uint8{1, 99},
						SlcPtrUint16Field:  &[]uint16{1, 999},
						SlcPtrUint32Field:  &[]uint32{1, 999},
						SlcPtrUint64Field:  &[]uint64{1, 999},
						SlcPtrFloat32Field: &[]float32{80.1, 10.1},
						SlcPtrFloat64Field: &[]float64{80.1, 10.1},
					},
					SubPtr2: &TestStructPtr{
						StrField:           &arg4,
						IntField:           &arg5,
						Int8Field:          &arg6,
						Int16Field:         &arg7,
						Int32Field:         &arg8,
						Int64Field:         &arg9,
						UintField:          &arg10,
						Uint8Field:         &arg11,
						Uint16Field:        &arg12,
						Uint32Field:        &arg13,
						Uint64Field:        &arg14,
						Float32Field:       &arg15,
						Float64Field:       &arg16,
						SlcStrField:        []*string{&arg17, &arg18},
						SlcIntField:        []*int{&arg19, &arg20},
						SlcInt8Field:       []*int8{&arg21, &arg22},
						SlcInt16Field:      []*int16{&arg23, &arg24},
						SlcInt32Field:      []*int32{&arg25, &arg26},
						SlcInt64Field:      []*int64{&arg27, &arg28},
						SlcUintField:       []*uint{&arg29, &arg30},
						SlcUint8Field:      []*uint8{&arg31, &arg32},
						SlcUint16Field:     []*uint16{&arg33, &arg34},
						SlcUint32Field:     []*uint32{&arg35, &arg36},
						SlcUint64Field:     []*uint64{&arg37, &arg38},
						SlcFloat32Field:    []*float32{&arg39, &arg40},
						SlcFloat64Field:    []*float64{&arg41, &arg42},
						SlcPtrStrField:     &[]*string{&arg43, &arg44},
						SlcPtrIntField:     &[]*int{&arg45, &arg46},
						SlcPtrInt8Field:    &[]*int8{&arg47, &arg48},
						SlcPtrInt16Field:   &[]*int16{&arg49, &arg50},
						SlcPtrInt32Field:   &[]*int32{&arg51, &arg52},
						SlcPtrInt64Field:   &[]*int64{&arg53, &arg54},
						SlcPtrUintField:    &[]*uint{&arg55, &arg56},
						SlcPtrUint8Field:   &[]*uint8{&arg57, &arg58},
						SlcPtrUint16Field:  &[]*uint16{&arg59, &arg60},
						SlcPtrUint32Field:  &[]*uint32{&arg61, &arg62},
						SlcPtrUint64Field:  &[]*uint64{&arg63, &arg64},
						SlcPtrFloat32Field: &[]*float32{&arg65, &arg66},
						SlcPtrFloat64Field: &[]*float64{&arg67, &arg68},
					},
				},
			},
			want: &TestStructMixedRecursive{
				StrField:    "te",
				StrPtrField: &res1,
				Sub1: TestStructMixedRecursiveSub{
					StrField:    "su",
					StrPtrField: &res2,
				},
				SubPtr1: &TestStructMixedRecursiveSub{
					StrField:    "su",
					StrPtrField: &res3,
				},
				SliSub1: []TestStructMixedRecursiveSub{
					{
						StrField:    "su",
						StrPtrField: &res69,
					},
					{
						StrField:    "su",
						StrPtrField: &res70,
					},
				},
				SliPtrSubPtr1: &[]*TestStructMixedRecursiveSub{
					&TestStructMixedRecursiveSub{
						StrField:    "su",
						StrPtrField: &res71,
					},
					&TestStructMixedRecursiveSub{
						StrField:    "su",
						StrPtrField: &res72,
					},
				},
				Sub2: TestStruct{
					StrField:           "he",
					IntField:           11,
					Int8Field:          21,
					Int16Field:         31,
					Int32Field:         41,
					Int64Field:         51,
					UintField:          61,
					Uint8Field:         71,
					Uint16Field:        81,
					Uint32Field:        91,
					Uint64Field:        101,
					Float32Field:       22.3,
					Float64Field:       42.3,
					SlcStrField:        []string{"he", "wo"},
					SlcIntField:        []int{11, 12},
					SlcInt8Field:       []int8{21, 22},
					SlcInt16Field:      []int16{31, 32},
					SlcInt32Field:      []int32{41, 42},
					SlcInt64Field:      []int64{51, 52},
					SlcUintField:       []uint{61, 62},
					SlcUint8Field:      []uint8{71, 72},
					SlcUint16Field:     []uint16{81, 82},
					SlcUint32Field:     []uint32{91, 92},
					SlcUint64Field:     []uint64{101, 102},
					SlcFloat32Field:    []float32{22.3, 22.2},
					SlcFloat64Field:    []float64{42.3, 42.2},
					SlcPtrStrField:     &[]string{"he", "wo"},
					SlcPtrIntField:     &[]int{11, 12},
					SlcPtrInt8Field:    &[]int8{21, 22},
					SlcPtrInt16Field:   &[]int16{31, 32},
					SlcPtrInt32Field:   &[]int32{41, 42},
					SlcPtrInt64Field:   &[]int64{51, 52},
					SlcPtrUintField:    &[]uint{61, 62},
					SlcPtrUint8Field:   &[]uint8{71, 72},
					SlcPtrUint16Field:  &[]uint16{81, 82},
					SlcPtrUint32Field:  &[]uint32{91, 92},
					SlcPtrUint64Field:  &[]uint64{101, 102},
					SlcPtrFloat32Field: &[]float32{22.3, 22.2},
					SlcPtrFloat64Field: &[]float64{42.3, 42.2},
				},
				SubPtr2: &TestStructPtr{
					StrField:           &res4,
					IntField:           &res5,
					Int8Field:          &res6,
					Int16Field:         &res7,
					Int32Field:         &res8,
					Int64Field:         &res9,
					UintField:          &res10,
					Uint8Field:         &res11,
					Uint16Field:        &res12,
					Uint32Field:        &res13,
					Uint64Field:        &res14,
					Float32Field:       &res15,
					Float64Field:       &res16,
					SlcStrField:        []*string{&res17, &res18},
					SlcIntField:        []*int{&res19, &res20},
					SlcInt8Field:       []*int8{&res21, &res22},
					SlcInt16Field:      []*int16{&res23, &res24},
					SlcInt32Field:      []*int32{&res25, &res26},
					SlcInt64Field:      []*int64{&res27, &res28},
					SlcUintField:       []*uint{&res29, &res30},
					SlcUint8Field:      []*uint8{&res31, &res32},
					SlcUint16Field:     []*uint16{&res33, &res34},
					SlcUint32Field:     []*uint32{&res35, &res36},
					SlcUint64Field:     []*uint64{&res37, &res38},
					SlcFloat32Field:    []*float32{&res39, &res40},
					SlcFloat64Field:    []*float64{&res41, &res42},
					SlcPtrStrField:     &[]*string{&res43, &res44},
					SlcPtrIntField:     &[]*int{&res45, &res46},
					SlcPtrInt8Field:    &[]*int8{&res47, &res48},
					SlcPtrInt16Field:   &[]*int16{&res49, &res50},
					SlcPtrInt32Field:   &[]*int32{&res51, &res52},
					SlcPtrInt64Field:   &[]*int64{&res53, &res54},
					SlcPtrUintField:    &[]*uint{&res55, &res56},
					SlcPtrUint8Field:   &[]*uint8{&res57, &res58},
					SlcPtrUint16Field:  &[]*uint16{&res59, &res60},
					SlcPtrUint32Field:  &[]*uint32{&res61, &res62},
					SlcPtrUint64Field:  &[]*uint64{&res63, &res64},
					SlcPtrFloat32Field: &[]*float32{&res65, &res66},
					SlcPtrFloat64Field: &[]*float64{&res67, &res68},
				},
			},
			wantErr: false,
		},
		{
			name: "Returns an error if there are problems with the struct tags",
			args: args{
				s: &TestBadStruct{
					Int64Field: 10,
				},
			},
			want: &TestBadStruct{
				Int64Field: 10,
			},
			wantErr: true,
		},
		{
			name: "Returns an error if there are problems with a nested struct tags",
			args: args{
				s: &TestBadNestedStruct{
					Sub: TestBadStruct{
						Int64Field: 10,
					},
				},
			},
			want: &TestBadNestedStruct{
				Sub: TestBadStruct{
					Int64Field: 10,
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := s.Sanitize(tt.args.s); (err != nil) != tt.wantErr {
				t.Errorf("Sanitize() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.s, tt.want) {
				t.Errorf("Sanitize() - got %+v but wanted %+v", tt.args.s, tt.want)
			}
		})
	}
}
