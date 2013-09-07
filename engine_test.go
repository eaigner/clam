package clam

import (
	"os"
	"testing"
)

func TestScan(t *testing.T) {
	engine := New()

	compileAndScan := func(t *testing.T, engine Engine) {
		if engine.IsCompiled() {
			t.Fatal("engine already compiled")
		}

		err := engine.Compile("cvd")
		if err != nil {
			t.Fatal(err)
		}

		if !engine.IsCompiled() {
			t.Fatal("engine should be compiled")
		}

		badFile, err := os.Open("testdata/eicar")
		if err != nil {
			t.Fatal(err)
		}

		err = engine.Scan(badFile)
		if err == nil {
			t.Fatal("should report virus error")
		}

		cleanFile, err := os.Open("testdata/clean.txt")
		if err != nil {
			t.Fatal(err)
		}

		err = engine.Scan(cleanFile)
		if err != nil {
			t.Fatal(err)
		}
	}

	t.Log("first run")

	compileAndScan(t, engine)

	engine.Destroy()

	t.Log("second run")

	compileAndScan(t, engine)
}
