package db

import "testing"

func TestEffectiveMinMatches_ZeroValue(t *testing.T) {
	c := Confirm{Type: ConfirmTypeKeyword, Patterns: []string{"test"}, MinMatches: 0}
	if got := c.EffectiveMinMatches(); got != 1 {
		t.Errorf("MinMatches=0: want 1, got %d", got)
	}
}

func TestEffectiveMinMatches_NegativeValue(t *testing.T) {
	c := Confirm{Type: ConfirmTypeKeyword, Patterns: []string{"test"}, MinMatches: -3}
	if got := c.EffectiveMinMatches(); got != 1 {
		t.Errorf("MinMatches=-3: want 1, got %d", got)
	}
}

func TestEffectiveMinMatches_PositiveValue(t *testing.T) {
	c := Confirm{Type: ConfirmTypeRegex, Patterns: []string{"a", "b", "c"}, MinMatches: 2}
	if got := c.EffectiveMinMatches(); got != 2 {
		t.Errorf("MinMatches=2: want 2, got %d", got)
	}
}

func TestEffectiveMinMatches_One(t *testing.T) {
	c := Confirm{Type: ConfirmTypeKeyword, Patterns: []string{"x"}, MinMatches: 1}
	if got := c.EffectiveMinMatches(); got != 1 {
		t.Errorf("MinMatches=1: want 1, got %d", got)
	}
}
