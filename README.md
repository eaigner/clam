clamav bindings for Go

You will need `pkg-config` and `clamav` installed to compile this package. If you are on OSX you can install those using homebrew.

    brew install pkgconfig
    brew install clamav

## Example

    engine := clam.New()

    err = engine.Compile("cvd")
    if err != nil {
      panic(err)
    }

    // Scan file that contains virus
    file, err := os.Open("eicar")
    if err != nil {
      panic(err)
    }

    // If a virus is found a VirusError is returned
    err = engine.Scan(file)
    if err != nil {
      fmt.Println("virus found:", err)
    }

    // If you want to refresh the engine, call Destroy() and recompile with Compile()
