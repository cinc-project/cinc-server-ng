package differential

import (
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/chefjson"
)

func parsed(t *testing.T, doc string) any {
	t.Helper()
	v, err := chefjson.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return Normalize(v, "")
}

func fields(diffs []Difference) map[string]Difference {
	out := map[string]Difference{}
	for _, d := range diffs {
		out[d.Field] = d
	}
	return out
}

// The harness compares what a client receives, not what it decodes to: member
// order, repeated names and the written form of a number all reach a client,
// and decoding into map[string]any and float64 erased every one of them.
func TestCompareSeesWhatDecodingHid(t *testing.T) {
	ref := parsed(t, `{"a":1,"b":{"x":1.0,"y":12345678901234567890,"z":"s"},"k":1}`)
	can := parsed(t, `{"b":{"x":1,"y":12345678901234567000,"z":"s"},"a":1,"k":1,"k":2}`)
	got := fields(compare("step", "", ref, can))

	for field, want := range map[string][2]string{
		"(body){members}": {"a,b,k", "b,a,k,k"},
		"b.x":             {"1.0", "1"},
		"b.y":             {"12345678901234567890", "12345678901234567000"},
	} {
		d, ok := got[field]
		if !ok {
			t.Errorf("no difference reported for %s; got %v", field, got)
			continue
		}
		if render(d.Reference) != want[0] || render(d.Candidate) != want[1] {
			t.Errorf("%s: reference %s, candidate %s; want %s, %s", field, render(d.Reference), render(d.Candidate), want[0], want[1])
		}
	}
	if len(got) != 3 {
		t.Errorf("got %d differences, want 3: %v", len(got), got)
	}
}

// A member missing on one side is reported once, as missing, not again as an
// ordering difference.
func TestMissingMemberIsNotAlsoAnOrderDifference(t *testing.T) {
	got := compare("step", "", parsed(t, `{"a":1,"b":2,"c":3}`), parsed(t, `{"a":1,"c":3}`))
	if len(got) != 1 || got[0].Field != "b" {
		t.Errorf("got %v, want only b missing", got)
	}
}

func TestIdenticalDocumentsCompareEqual(t *testing.T) {
	doc := `{"name":"n","normal":{"tags":["a"],"n":1.5,"big":12345678901234567890},"run_list":[]}`
	if got := compare("step", "", parsed(t, doc), parsed(t, doc)); len(got) != 0 {
		t.Errorf("identical documents differ: %v", got)
	}
}

// Values in a report and a baseline are rendered as JSON, so they are the
// bytes a client saw and they render the same on every run.
func TestRenderIsDeterministicJSON(t *testing.T) {
	v := parsed(t, `{"b":[1.0,{"y":null,"x":true}],"a":"s"}`)
	if got := render(v); got != `{"b":[1.0,{"y":null,"x":true}],"a":"s"}` {
		t.Errorf("render = %s", got)
	}
	if got := render("plain"); got != "plain" {
		t.Errorf("render(string) = %s", got)
	}
}
