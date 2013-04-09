package clam

import (
	"os"
	"testing"
)

func newClam(t *testing.T) Engine {
	engine, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.LoadCvd("cvd"); err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestScan(t *testing.T) {
	engine := newClam(t)
	badFile, err := os.Open("testdata/eicar")
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Scan(badFile)
	if err != nil {
		t.Fatal(err)
	}
	if x := result.HasVirus(); !x {
		t.Fatal(x)
	}
	cleanFile, err := os.Open("testdata/clean.txt")
	if err != nil {
		t.Fatal(err)
	}
	result, err = engine.Scan(cleanFile)
	if err != nil {
		t.Fatal(err)
	}
	if x := result.HasVirus(); x {
		t.Fatal(x)
	}
}
