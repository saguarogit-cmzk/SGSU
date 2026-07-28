package nftgen

import (
	"strings"
	"testing"
)

func TestScheduledRule(t *testing.T) {
	c := baseWithObjects()
	c.Rules = append(c.Rules, Rule{
		Name: "guests night", Action: "drop", Proto: "any", SrcAlias: "guests", Enabled: true,
		Schedule: &Schedule{Days: []int{1, 2, 3, 4, 5}, Start: "22:00", End: "06:00"},
	})
	out, err := c.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "meta day { 1, 2, 3, 4, 5 }") {
		t.Errorf("missing meta day match:\n%s", out)
	}
	if !strings.Contains(out, `meta hour "22:00"-"06:00"`) {
		t.Errorf("missing meta hour match:\n%s", out)
	}
}

func TestScheduleValidation(t *testing.T) {
	bad := []*Schedule{
		{Days: []int{7}},               // weekday out of range
		{Start: "22:00"},               // only one clock bound
		{Start: "9:00", End: "10:00"},  // hour not zero-padded HH:MM
		{Start: "08:00", End: "25:00"}, // hour out of range
	}
	for _, s := range bad {
		c := baseWithObjects()
		c.Rules = append(c.Rules, Rule{Name: "sched bad", Action: "drop", Proto: "any", Enabled: true, Schedule: s})
		if err := c.Validate(); err == nil {
			t.Errorf("expected validation error for schedule %+v", s)
		}
	}
	// a valid days-only schedule (weekend) passes validation
	c := baseWithObjects()
	c.Rules = append(c.Rules, Rule{Name: "weekend", Action: "drop", Proto: "any", Enabled: true, Schedule: &Schedule{Days: []int{0, 6}}})
	if err := c.Validate(); err != nil {
		t.Errorf("valid schedule rejected: %v", err)
	}
}
