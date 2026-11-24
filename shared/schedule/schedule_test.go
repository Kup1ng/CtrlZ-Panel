package schedule

import (
	"testing"
	"time"
	_ "time/tzdata"
)

func gridOf(f func(i int) byte) []byte {
	g := make([]byte, Cells)
	for i := range g {
		g[i] = f(i)
	}
	return g
}

func TestCellBoundaries(t *testing.T) {
	s, err := New(0, nil, gridOf(func(i int) byte { return byte(i % 200) }), 200)
	if err != nil {
		t.Fatal(err)
	}
	// 2026-11-01 is a Sunday. 00:00 UTC is cell 0.
	sun := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC).Unix()
	for _, c := range []struct {
		off  int64
		want int
	}{{0, 0}, {29*60 + 59, 0}, {30 * 60, 1}, {24 * 3600, 48}, {7*24*3600 - 1, 335}, {7 * 24 * 3600, 0}} {
		if got := s.CellIndex(sun + c.off); got != c.want {
			t.Errorf("sunday+%d: got %d want %d", c.off, got, c.want)
		}
	}
	// The epoch is a Thursday: day 4, cell 192.
	if got := s.CellIndex(0); got != 4*48 {
		t.Errorf("epoch cell %d", got)
	}
	// Before the epoch must stay in range (floor division).
	if got := s.CellIndex(-1); got != 4*48-1 {
		t.Errorf("-1: %d", got)
	}
}

func TestTehranOffset(t *testing.T) {
	// Asia/Tehran is UTC+3:30 with no DST since 2022, so 20:30 UTC is local midnight.
	s, _ := New(3*3600+1800, nil, gridOf(func(i int) byte { return byte(i % 200) }), 200)
	sat := time.Date(2026, 11, 7, 20, 29, 59, 0, time.UTC).Unix() // Saturday 23:59:59 local
	if got := s.CellIndex(sat); got != 6*48+47 {
		t.Errorf("before midnight: %d", got)
	}
	if got := s.CellIndex(sat + 1); got != 0 {
		t.Errorf("at midnight: %d want 0 (Sunday)", got)
	}
}

func TestTransitionsAndHold(t *testing.T) {
	T := int64(1_000_000)
	U := T + 86400
	s, _ := New(0, []Transition{{T, 3600}, {U, 0}}, make([]byte, Cells), 0)
	if s.Offset(T-1) != 0 || s.Offset(T) != 3600 || s.Offset(U-1) != 3600 || s.Offset(U) != 0 || s.Offset(U+10*86400) != 0 {
		t.Fatal("offset selection")
	}
}

func TestNewRejects(t *testing.T) {
	if _, err := New(0, nil, make([]byte, 335), 0); err != ErrGridSize {
		t.Error(err)
	}
	if _, err := New(0, []Transition{{5, 1}, {5, 2}}, make([]byte, Cells), 0); err != ErrTransitionOrder {
		t.Error(err)
	}
	g := make([]byte, Cells)
	g[7] = 3
	if _, err := New(0, nil, g, 2); err != ErrWindowRange {
		t.Error(err)
	}
}

func TestBuildTransitionsDST(t *testing.T) {
	loc, err := time.LoadLocation("Europe/London")
	if err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	to := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	base, tr := BuildTransitions(loc, from, to)
	if base != 0 || len(tr) != 2 {
		t.Fatalf("base %d transitions %v", base, tr)
	}
	if tr[0].At != time.Date(2026, 3, 29, 1, 0, 0, 0, time.UTC).Unix() || tr[0].Offset != 3600 {
		t.Errorf("spring %v", tr[0])
	}
	if tr[1].At != time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC).Unix() || tr[1].Offset != 0 {
		t.Errorf("fall %v", tr[1])
	}
	tehran, _ := time.LoadLocation("Asia/Tehran")
	b2, t2 := BuildTransitions(tehran, from, to)
	if b2 != 12600 || len(t2) != 0 {
		t.Errorf("tehran %d %v", b2, t2)
	}
}
