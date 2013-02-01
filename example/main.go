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

	fmt.Println("loading cvds...")

	engine, err := clam.New()
	if err != nil {
		panic(err)
	}

	err = engine.LoadCvd(path.Join(wd, "cvd"))
	if err != nil {
		panic(err)
	}

	fmt.Println("scanning...")

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
	} else {
		fmt.Println("file clean")
	}
	fmt.Printf("scanned %d bytes\n", result.BytesScanned)

	// scan clean file
	file, err = os.Open("clean.txt")
	if err != nil {
		panic(err)
	}
	result, err = engine.Scan(file)
	if err != nil {
		panic(err)
	}
	if result.HasVirus() {
		fmt.Println("virus detected!", result.VirusName)
	} else {
		fmt.Println("file clean")
	}
	fmt.Printf("scanned %d bytes\n", result.BytesScanned)

	fmt.Println("done.")
}
