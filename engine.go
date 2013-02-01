// +build !windows

package clam

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
)

var std *engine = new()

type engine struct {
	engine *C.struct_cl_engine
}

func new() *engine {
	var ret C.int

	// initialize struct
	ret = C.cl_init(C.CL_INIT_DEFAULT)
	if ret != C.CL_SUCCESS {
		panic(fmt.Sprintf("cannot initialize clamav (%s)", C.GoString(C.cl_strerror(ret))))
	}

	// create new engine
	e := &engine{}
	e.engine = C.cl_engine_new()
	if e.engine == nil {
		panic("cannot create new clamav engine")
	}
	return e
}

func LoadCvd(path string) error {
	var ret C.int
	var sigs C.uint = 0

	// load signatures
	ret = C.cl_load(C.CString(path), std.engine, &sigs, C.CL_DB_STDOPT)
	if ret != C.CL_SUCCESS {
		return fmt.Errorf("could not load vcds: %s", C.GoString(C.cl_strerror(ret)))
	}

	// compile engine
	ret = C.cl_engine_compile(std.engine)
	if ret != C.CL_SUCCESS {
		return fmt.Errorf("could not compile engine: %s", C.GoString(C.cl_strerror(ret)))
	}
	return nil
}

func Scan(file *os.File) (*ScanResult, error) {
	var ret C.int
	var fd C.int = C.int(file.Fd())
	var virname *C.char
	var size C.ulong = 0

	// scan file
	result := &ScanResult{}
	ret = C.cl_scandesc(fd, &virname, &size, std.engine, C.CL_SCAN_STDOPT)
	if ret == C.CL_VIRUS {
		result.VirusName = C.GoString(virname)
	} else if ret == C.CL_CLEAN {
		// do nothing
	} else {
		return nil, fmt.Errorf("error: %s", C.GoString(C.cl_strerror(ret)))
	}

	// get scanned bytes
	result.BytesScanned = uint64(size * C.CL_COUNT_PRECISION)

	return result, nil
}

type ScanResult struct {
	VirusName    string
	BytesScanned uint64
}

func (r *ScanResult) HasVirus() bool {
	return len(r.VirusName) > 0
}
