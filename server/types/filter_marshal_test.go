package relay

import (
	"encoding/json"
	"testing"
	"time"
)

func TestFilterMarshalsNIP01WireForm(t *testing.T) {
	since, until := time.Unix(1700000000, 0), time.Unix(1700000600, 0)
	limit := 5
	f := Filter{
		Authors: []string{"ab"},
		Kinds:   []int{3333},
		Tags:    map[string][]string{"e": {"cd"}},
		Since:   &since,
		Until:   &until,
		Limit:   &limit,
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"#e":["cd"],"authors":["ab"],"kinds":[3333],"limit":5,"since":1700000000,"until":1700000600}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
}
