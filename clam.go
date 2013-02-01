// +build !windows

package main

/*
#cgo pkg-config: libclamav

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <clamav.h>
*/
import "C"
import (
	"fmt"
	"os"
	"path"
)

func main() {
	var fd, ret C.int
	var size C.ulong = 0
	var sigs C.uint = 0
	var mb C.double // long double in c (?)
	var virname *C.char
	var engine *C.struct_cl_engine

	wd, _ := os.Getwd()
	cwdDir := path.Join(wd, "cvd")
	fmt.Println("database dir:", cwdDir)

	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <file>\n", os.Args[0])
		os.Exit(2)
	}

	fileName := os.Args[1]
	fd = C.open(C.CString(fileName), C.O_RDONLY)
	if fd == -1 {
		fmt.Printf("can't open file %s\n", fileName)
		os.Exit(2)
	}
	defer C.close(fd)

	ret = C.cl_init(C.CL_INIT_DEFAULT)
	if ret != C.CL_SUCCESS {
		fmt.Printf("can't initialize libclamav: %s\n", C.cl_strerror(ret))
		os.Exit(2)
	}

	engine = C.cl_engine_new()
	if engine == nil {
		fmt.Println("can't create new engine")
		os.Exit(2)
	}
	defer C.cl_engine_free(engine)

	fmt.Printf("clamav db dir: %s\n", C.GoString(C.cl_retdbdir()))

	ret = C.cl_load(C.CString(cwdDir), engine, &sigs, C.CL_DB_STDOPT)
	if ret != C.CL_SUCCESS {
		fmt.Printf("cl_load: %s\n", C.GoString(C.cl_strerror(ret)))
		os.Exit(2)
	}

	fmt.Printf("loaded %u signatures\n", sigs)

	ret = C.cl_engine_compile(engine)
	if ret != C.CL_SUCCESS {
		fmt.Printf("could not init db: %s\n", C.cl_strerror(ret))
		os.Exit(2)
	}

	ret = C.cl_scandesc(fd, &virname, &size, engine, C.CL_SCAN_STDOPT)
	if ret == C.CL_VIRUS {
		fmt.Printf("virus detected! %s\n", virname)
	} else if ret == C.CL_CLEAN {
		fmt.Println("no virus detected")
	} else {
		fmt.Printf("error: %s\n", C.cl_strerror(ret))
		os.Exit(2)
	}

	mb = C.double(size*(C.CL_COUNT_PRECISION/1024)) / 1024.0

	fmt.Printf("data scanned: %2.2d MB\n", mb)

	if ret == C.CL_VIRUS {
		os.Exit(1)
	}
	os.Exit(0)
}
