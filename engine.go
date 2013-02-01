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
	"runtime"
	"sync"
)

type Engine interface {
	// LoadCvd loads all virus definitions found in the specified directory
	LoadCvd(path string) error

	// Scan scans the file
	Scan(file *os.File) (*ScanResult, error)

	// Destroy destructs the engine
	Destroy()
}

type engine struct {
	engine *C.struct_cl_engine
	mtx    sync.Mutex
}

func New() (Engine, error) {
	var ret C.int

	// initialize struct
	ret = C.cl_init(C.CL_INIT_DEFAULT)
	if ret != C.CL_SUCCESS {
		return nil, fmt.Errorf("cannot initialize clamav (%s)", C.GoString(C.cl_strerror(ret)))
	}

	// create new engine
	e := &engine{}
	e.engine = C.cl_engine_new()
	if e.engine == nil {
		return nil, fmt.Errorf("cannot create new clamav engine")
	}

	// set a finalizer
	runtime.SetFinalizer(e, func(e2 *engine) {
		e2.Destroy()
	})

	return e, nil
}

func (e *engine) LoadCvd(path string) error {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	var ret C.int
	var sigs C.uint = 0

	// load signatures
	ret = C.cl_load(C.CString(path), e.engine, &sigs, C.CL_DB_STDOPT)
	if ret != C.CL_SUCCESS {
		return fmt.Errorf("could not load vcds: %s", C.GoString(C.cl_strerror(ret)))
	}

	// compile engine
	ret = C.cl_engine_compile(e.engine)
	if ret != C.CL_SUCCESS {
		return fmt.Errorf("could not compile engine: %s", C.GoString(C.cl_strerror(ret)))
	}
	return nil
}

func (e *engine) Scan(file *os.File) (*ScanResult, error) {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	var ret C.int
	var fd C.int = C.int(file.Fd())
	var virname *C.char
	var size C.ulong = 0

	// scan file
	result := &ScanResult{}
	ret = C.cl_scandesc(fd, &virname, &size, e.engine, C.CL_SCAN_STDOPT)
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

func (e *engine) Destroy() {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	if e.engine != nil {
		C.cl_engine_free(e.engine)
		e.engine = nil
	}
}

type ScanResult struct {
	VirusName    string
	BytesScanned uint64
}

func (r *ScanResult) HasVirus() bool {
	return len(r.VirusName) > 0
}
