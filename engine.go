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
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
)

var (
	ErrAlreadyCompiled = errors.New("engine already compiled")
)

type Engine interface {
	// LoadCvd loads all virus definitions found in the specified directory
	LoadCvd(path string) error
	// IsCompiled returns true if the virus definitions were already loaded and the engine compiled
	IsCompiled() bool
	// Scan scans the file
	Scan(file *os.File) (*ScanResult, error)
}

type ScanResult struct {
	VirusName    string
	BytesScanned uint64
}

type engine struct {
	compiled bool
	engine   *C.struct_cl_engine
	mtx      sync.Mutex
}

var (
	gEng Engine
	gMtx sync.Mutex
)

func Clam() (Engine, error) {
	gMtx.Lock()
	defer gMtx.Unlock()
	if gEng != nil {
		return gEng, nil
	}
	var ret C.int

	// Initialize struct
	ret = C.cl_init(C.CL_INIT_DEFAULT)
	if ret != C.CL_SUCCESS {
		return nil, fmt.Errorf("cannot initialize clamav (%s)", C.GoString(C.cl_strerror(ret)))
	}

	// Create new engine
	e := &engine{}
	e.engine = C.cl_engine_new()
	if e.engine == nil {
		return nil, fmt.Errorf("cannot create new clamav engine")
	}

	// Set a finalizer
	runtime.SetFinalizer(e, func(e2 *engine) {
		e2.destroy()
	})

	gEng = e

	return e, nil
}

func (e *engine) LoadCvd(path string) error {
	if e.compiled {
		return ErrAlreadyCompiled
	}
	e.mtx.Lock()
	defer e.mtx.Unlock()

	var ret C.int
	var sigs C.uint = 0

	// Load signatures
	ret = C.cl_load(C.CString(path), e.engine, &sigs, C.CL_DB_STDOPT)
	if ret != C.CL_SUCCESS {
		return fmt.Errorf("could not load vcds: %s", C.GoString(C.cl_strerror(ret)))
	}

	// Compile engine
	ret = C.cl_engine_compile(e.engine)
	if ret != C.CL_SUCCESS {
		return fmt.Errorf("could not compile engine: %s", C.GoString(C.cl_strerror(ret)))
	}

	e.compiled = true

	return nil
}

func (e *engine) IsCompiled() bool {
	return e.compiled
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

func (r *ScanResult) HasVirus() bool {
	return len(r.VirusName) > 0
}

func (e *engine) destroy() {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	if e.engine != nil {
		C.cl_engine_free(e.engine)
		e.engine = nil
	}
}
