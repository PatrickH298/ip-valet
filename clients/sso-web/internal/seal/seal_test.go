package seal

import (
	"errors"
	"testing"
	"time"
)

func TestSeal(t *testing.T) {
	s := New()
	now := time.Now()
	s.Now = func() time.Time { return now }
	type v struct{ A string }
	tok, err := s.Seal("p", time.Minute, v{A: "x"})
	if err != nil {
		t.Fatal(err)
	}
	var got v
	if err := s.Open("p", tok, &got); err != nil || got.A != "x" {
		t.Fatal(got, err)
	}
	if err := s.Open("other", tok, &got); !errors.Is(err, ErrInvalid) {
		t.Fatal("opened for another purpose:", err)
	}
	if err := New().Open("p", tok, &got); !errors.Is(err, ErrInvalid) {
		t.Fatal("opened with another key:", err)
	}
	if err := s.Open("p", tok[:len(tok)-2]+"AA", &got); !errors.Is(err, ErrInvalid) {
		t.Fatal("tampered signature accepted:", err)
	}
	if err := s.Open("p", "x"+tok, &got); !errors.Is(err, ErrInvalid) {
		t.Fatal("tampered body accepted:", err)
	}
	s.Now = func() time.Time { return now.Add(time.Minute) }
	if err := s.Open("p", tok, &got); !errors.Is(err, ErrExpired) {
		t.Fatal("expired value accepted:", err)
	}
	a1, again := s.Tag("a", "1"), s.Tag("a", "1")
	if a1 != again || a1 == s.Tag("a", "2") || a1 == s.Tag("b", "1") || a1 == New().Tag("a", "1") {
		t.Fatal("tags")
	}
}
