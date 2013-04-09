package clam

import (
	"os"
	"testing"
)

func TestScan(t *testing.T) {
	engine, err := Clam()
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.LoadCvd("cvd"); err != nil {
		t.Fatal(err)
	}
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

	// Calling Clam() for a second time must not yield error
	engine2, err := Clam()
	if err != nil {
		t.Fatal(err)
	}
	if engine != engine2 {
		t.Fatal(engine, engine2)
	}

	// Calling LoadCvd() again must yield error
	err = engine2.LoadCvd("cvd")
	if err != ErrAlreadyCompiled {
		t.Fatal(err)
	}
}
