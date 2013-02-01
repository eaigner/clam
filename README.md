clamav bindings for Go

You will need `pkg-config` and `clamav` installed to compile this package. If you are on OSX you can install those using homebrew.

    brew install pkgconfig
    brew install clamav

## Example

    package main

    import (
      "fmt"
      "github.com/eaigner/clam"
      "os"
      "path"
    )

    func main() {
      wd, err := os.Getwd()
      if err != nil {
        panic(err)
      }

      // create a clamav engine
      engine, err := clam.New()
      if err != nil {
        panic(err)
      }

      // load directory with cvd virus definitions
      err = engine.LoadCvd(path.Join(wd, "cvd"))
      if err != nil {
        panic(err)
      }

      // scan file that contains virus
      file, err := os.Open("eicar")
      if err != nil {
        panic(err)
      }
      result, err := engine.Scan(file)
      if err != nil {
        panic(err)
      }
      if result.HasVirus() {
        fmt.Println("virus detected!", result.VirusName)
      }
      fmt.Printf("scanned %d bytes\n", result.BytesScanned)
    }
