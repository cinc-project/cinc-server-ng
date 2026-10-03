package chefjson

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

// The expected outputs below are the bytes a real Chef Infra Server (Cinc
// Server, erchef) stored and returned for each input, captured by sending the
// input as a node attribute and reading the node back. They are the
// specification; when one disagrees with intuition, the server wins.

func TestNormalizeMatchesErchef(t *testing.T) {
	cases := []struct{ name, in, want string }{
		// Structure: key order is the client's, at every depth.
		{"key order", `{"zeta":1,"alpha":2,"Mid":{"b":1,"a":2},"arr":[3,1,{"y":1,"x":2}]}`,
			`{"zeta":1,"alpha":2,"Mid":{"b":1,"a":2},"arr":[3,1,{"y":1,"x":2}]}`},
		{"whitespace", "{\n  \"name\" : \"n\",\n  \"normal\" : { \"b\" : [ 1 , 2 ] , \"a\" : true }\n}\n",
			`{"name":"n","normal":{"b":[1,2],"a":true}}`},
		{"duplicates kept", `{"k":1,"k":2}`, `{"k":1,"k":2}`},
		{"literals", `[true,false,null]`, `[true,false,null]`},
		{"empty", `{"o":{},"a":[]}`, `{"o":{},"a":[]}`},

		// Integers are exact at any size.
		{"big int", `12345678901234567890`, `12345678901234567890`},
		{"bigger int", `123456789012345678901234567890`, `123456789012345678901234567890`},
		{"negative big int", `-12345678901234567890`, `-12345678901234567890`},
		{"past 2^53", `9007199254740993`, `9007199254740993`},
		{"zero", `0`, `0`},
		{"negative zero int", `-0`, `0`},

		// Floats are doubles, written in shortest form, and stay floats.
		{"one point zero", `1.0`, `1.0`},
		{"trailing zero", `1.10`, `1.1`},
		{"exponent integral", `1e3`, `1000.0`},
		{"upper exponent", `1E2`, `100.0`},
		{"plus exponent", `2.5e+5`, `250000.0`},
		{"exponent of one", `1.0e0`, `1.0`},
		{"scaled fraction", `0.1e1`, `1.0`},
		{"hundred", `100.0`, `100.0`},
		{"small exponent", `1.5E-7`, `1.5e-7`},
		{"1e-6 is decimal", `1e-6`, `0.000001`},
		{"0.000001", `0.000001`, `0.000001`},
		{"1e-7 is exponent", `1e-7`, `1e-7`},
		{"1e16", `1e16`, `10000000000000000.0`},
		{"1.2345e15", `1.2345e15`, `1234500000000000.0`},
		{"1e17 float", `100000000000000000.0`, `100000000000000000.0`},
		{"1e20 is decimal", `1e20`, `100000000000000000000.0`},
		{"1e21 is exponent", `1e21`, `1e+21`},
		{"1e22", `1e22`, `1e+22`},
		{"large", `1.5e300`, `1.5e+300`},
		{"max", `1.7976931348623157e308`, `1.7976931348623157e+308`},
		{"fraction", `0.1`, `0.1`},
		{"third", `0.333333333333333333333`, `0.3333333333333333`},
		{"decimal", `123456789.123`, `123456789.123`},
		{"negative", `-1.5`, `-1.5`},
		{"4.35", `4.35`, `4.35`},
		{"2.675", `2.675`, `2.675`},
		{"0.1+0.2", `0.30000000000000004`, `0.30000000000000004`},
		{"rounded to double", `9007199254740993.0`, `9007199254740992.0`},
		{"float zero", `0.0`, `0.0`},
		{"negative float zero", `-0.0`, `0.0`},
		{"negative exponent zero", `-0e0`, `0.0`},
		{"underflow", `1e-400`, `0.0`},
		{"subnormal", `5e-324`, `0.0`},

		// Strings are decoded and re-escaped minimally; control characters other
		// than the short escapes use upper-case hex.
		{"unicode escape", `"caf\u00e9"`, `"café"`},
		{"upper-case escape", `"\u00E9"`, `"é"`},
		{"escaped slash", `"a\/b"`, `"a/b"`},
		{"html", `"<b>&amp;</b>"`, `"<b>&amp;</b>"`},
		{"line separator", "\"a\u2028b\"", "\"a\u2028b\""},
		{"escaped line separator", `"a\u2028b"`, "\"a\u2028b\""},
		{"escaped paragraph separator", `"a\u2029b"`, "\"a\u2029b\""},
		{"control", `"\u0001\u001f"`, `"\u0001\u001F"`},
		{"short escapes", `"\b\f\n\r\t"`, `"\b\f\n\r\t"`},
		{"quote and backslash", `"q\"b\\"`, `"q\"b\\"`},
		{"surrogate pair", `"\ud83d\ude80"`, `"🚀"`},
		{"literal emoji", `"🚀"`, `"🚀"`},
		{"nul", `"\u0000"`, `"\u0000"`},
		{"del", `"\u007f"`, "\"\x7f\""},
		{"c1 control", `"\u0085"`, "\"\u0085\""},
		{"bom", `"\ufeff"`, "\"\ufeff\""},
		{"noncharacter", `"\uffff"`, "\"\uffff\""},
		{"escaped keys", `{"\u00e9k":1,"a\/b":2,"z":{"\u0041":1}}`, `{"ék":1,"a/b":2,"z":{"A":1}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Normalize(strings.NewReader(c.in))
			if err != nil {
				t.Fatalf("Normalize(%s): %v", c.in, err)
			}
			if string(got) != c.want {
				t.Errorf("Normalize(%s)\n got %s\nwant %s", c.in, got, c.want)
			}
		})
	}
}

// Every one of these is a 400 "invalid JSON" from erchef.
func TestNormalizeRejectsWhatErchefRejects(t *testing.T) {
	cases := []struct{ name, in string }{
		{"invalid UTF-8", "{\"bad\":\"a\xff\xfeb\"}"},
		{"lone high surrogate", `{"v":"\ud800x"}`},
		{"lone low surrogate", `{"v":"\udc00x"}`},
		{"overflow", `{"huge":1e400}`},
		{"negative overflow", `{"huge":-1e400}`},
		{"trailing garbage", `{"name":"n"} x`},
		{"second value", `{}{}`},
		{"empty body", ``},
		{"truncated", `{"name":`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, err := Normalize(strings.NewReader(c.in)); err == nil {
				t.Errorf("Normalize(%q) = %s, want an error", c.in, got)
			}
		})
	}
}

// Normalizing is idempotent: the stored form normalizes to itself, so
// re-reading or re-loading a document never drifts.
func TestNormalizeIsIdempotent(t *testing.T) {
	in := `{"z":[1.0,1e21,-0,"\u0001\/é"],"a":{"k":1,"k":12345678901234567890}}`
	once, err := Normalize(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	twice, err := Normalize(strings.NewReader(string(once)))
	if err != nil {
		t.Fatal(err)
	}
	if string(once) != string(twice) {
		t.Errorf("not idempotent:\n once %s\ntwice %s", once, twice)
	}
}

// erchef reads a field from the first member that has its name.
func TestStringIsFirstMemberWins(t *testing.T) {
	doc := []byte(`{"normal":{"name":"nested"},"name":"first","name":"second","n":1}`)
	if got, ok := String(doc, "name"); !ok || got != "first" {
		t.Errorf(`String(name) = %q, %v; want "first", true`, got, ok)
	}
	if _, ok := String(doc, "n"); ok {
		t.Error("String reported a number member as a string")
	}
	if _, ok := String(doc, "missing"); ok {
		t.Error("String reported a missing member")
	}
	if _, ok := String([]byte(`[1]`), "name"); ok {
		t.Error("String reported a member of a non-object")
	}
}

func TestDecodeObjectFirstMemberWinsAndKeepsNumbers(t *testing.T) {
	m, err := DecodeObject([]byte(`{"name":"a","name":"b","x":{"k":1,"k":2},"n":12345678901234567890,"f":1.0,"l":[1,{"q":true}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if m["name"] != "a" {
		t.Errorf("name = %v, want the first member", m["name"])
	}
	if x := m["x"].(map[string]any); x["k"] != json.Number("1") {
		t.Errorf("nested duplicate = %v, want the first member", x["k"])
	}
	if m["n"] != json.Number("12345678901234567890") || m["f"] != json.Number("1.0") {
		t.Errorf("numbers = %v, %v; want their literals", m["n"], m["f"])
	}
	if l := m["l"].([]any); l[0] != json.Number("1") || l[1].(map[string]any)["q"] != true {
		t.Errorf("array = %v", l)
	}
	if _, err := DecodeObject([]byte(`[1]`)); err == nil {
		t.Error("DecodeObject accepted a non-object")
	}
}

// Edits through Object keep every other member where it was: Set replaces the
// first member of that name in place, or appends one, as erchef's ej:set does.
func TestObjectSetAndMarshal(t *testing.T) {
	v, err := Parse([]byte(`{"z":1,"id":"i","a":1.0,"k":1,"k":2}`))
	if err != nil {
		t.Fatal(err)
	}
	obj := v.(*Object)
	obj.Set("chef_type", "data_bag_item")
	obj.Set("k", "first replaced")
	obj.Set("data_bag", "bag")
	want := `{"z":1,"id":"i","a":1.0,"k":"first replaced","k":2,"chef_type":"data_bag_item","data_bag":"bag"}`
	if got := string(Marshal(obj)); got != want {
		t.Errorf("Marshal\n got %s\nwant %s", got, want)
	}
	if got, ok := obj.Get("k"); !ok || got != "first replaced" {
		t.Errorf("Get(k) = %v, %v", got, ok)
	}
}

func BenchmarkNormalizeNode(b *testing.B) {
	node := `{"name":"n","normal":{"tags":["a","b"],"n":12345678901234567890,"f":1.5},"automatic":{` +
		strings.Repeat(`"fs_k":{"kb_size":"1024","mount":"/","options":["rw","noatime"],"percent_used":12.5},`, 200) +
		`"x":1}}`
	b.SetBytes(int64(len(node)))
	for b.Loop() {
		if _, err := Normalize(strings.NewReader(node)); err != nil {
			b.Fatal(err)
		}
	}
}

// Whatever Normalize accepts, it writes as valid JSON that normalizes to
// itself and that decodes to the same value, integers digit for digit.
func FuzzNormalize(f *testing.F) {
	for _, seed := range []string{
		`{"a":1,"a":[1.0,-0,1e21,"\u0001\/"],"b":{"c":null,"d":true}}`,
		`12345678901234567890`, `"🚀"`, `[1e-7,0.000001,5e-324]`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out, err := Normalize(strings.NewReader(in))
		if err != nil {
			return
		}
		if !json.Valid(out) {
			t.Fatalf("Normalize(%q) = %q, not valid JSON", in, out)
		}
		again, err := Normalize(strings.NewReader(string(out)))
		if err != nil || string(again) != string(out) {
			t.Fatalf("not idempotent: %q -> %q -> %q (%v)", in, out, again, err)
		}
		var a, b any
		dec := json.NewDecoder(strings.NewReader(in))
		dec.UseNumber()
		if dec.Decode(&a) != nil {
			return // duplicate names decode differently; nothing to compare
		}
		dec = json.NewDecoder(strings.NewReader(string(out)))
		dec.UseNumber()
		if err := dec.Decode(&b); err != nil {
			t.Fatalf("decode %q: %v", out, err)
		}
		if !sameValue(a, b) {
			t.Fatalf("value changed: %q -> %q", in, out)
		}
	})
}

// sameValue compares decoded documents, treating numbers as equal when they
// are the same integer or the same double.
func sameValue(a, b any) bool {
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			if !sameValue(v, y[k]) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !sameValue(x[i], y[i]) {
				return false
			}
		}
		return true
	case json.Number:
		y, ok := b.(json.Number)
		if !ok {
			return false
		}
		if !strings.ContainsAny(string(x), ".eE") {
			return strings.TrimPrefix(string(x), "-") == "0" && y == "0" || x == y
		}
		fx, _ := x.Float64()
		fy, _ := y.Float64()
		return fx == fy || math.Abs(fx) < smallestNormal && fy == 0
	default:
		return a == b
	}
}
