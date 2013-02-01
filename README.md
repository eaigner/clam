clamav bindings for Go

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

      // load directory with cvd virus definitions
      err = clam.LoadCvd(path.Join(wd, "cvd"))
      if err != nil {
        panic(err)
      }

      // scan file that contains virus
      file, err := os.Open("eicar")
      if err != nil {
        panic(err)
      }
      result, err := clam.Scan(file)
      if err != nil {
        panic(err)
      }
      if result.HasVirus() {
        fmt.Println("virus detected!", result.VirusName)
      }
      fmt.Printf("scanned %d bytes\n", result.BytesScanned)
    }
