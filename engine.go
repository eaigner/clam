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
	"sync/atomic"
)

var (
	ErrAlreadyCompiled = errors.New("engine already compiled")
)

type Engine interface {
	// Compile compiles the engine using the virus definitions in cvdDir.
	Compile(cvdDir string) error

	// IsCompiled returns true if then engine is compiled.
	IsCompiled() bool

	// Scan scans the file for viruses, returns error if virus is found.
	Scan(file *os.File) error

	// Destroy destroys the engine.
	Destroy()
}

func init() {
	// Prepare libclamav
	var ret C.int
	ret = C.cl_init(C.CL_INIT_DEFAULT)
	if ret != C.CL_SUCCESS {
		panic("cannot initialize clamav:" + C.GoString(C.cl_strerror(ret)))
	}
}

func New() Engine {
	e := &clEngine{}
	runtime.SetFinalizer(e, func(e2 *clEngine) {
		e2.Destroy()
	})
	return e
}

type clEngine struct {
	compiled int32
	engine   *C.struct_cl_engine
	mtx      sync.Mutex
}

func (e *clEngine) Compile(cvdDir string) error {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	if e.IsCompiled() {
		return ErrAlreadyCompiled
	}

	// Create new engine
	e.engine = C.cl_engine_new()
	if e.engine == nil {
		return errors.New("failed to create new clamav engine")
	}

	// Load signatures
	var ret C.int
	var sigs C.uint = 0
	ret = C.cl_load(C.CString(cvdDir), e.engine, &sigs, C.CL_DB_STDOPT)
	if ret != C.CL_SUCCESS {
		return fmt.Errorf("could not load vcds: %s", C.GoString(C.cl_strerror(ret)))
	}

	// Compile engine
	ret = C.cl_engine_compile(e.engine)
	if ret != C.CL_SUCCESS {
		return fmt.Errorf("could not compile engine: %s", C.GoString(C.cl_strerror(ret)))
	}

	atomic.StoreInt32(&e.compiled, 1)

	return nil
}

func (e *clEngine) IsCompiled() bool {
	return (atomic.LoadInt32(&e.compiled) == 1)
}

func (e *clEngine) Scan(file *os.File) error {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	var ret C.int
	var fd C.int = C.int(file.Fd())
	var virname *C.char
	var size C.ulong = 0

	// Scan file
	var virName string
	ret = C.cl_scandesc(fd, &virname, &size, e.engine, C.CL_SCAN_STDOPT)
	if ret == C.CL_VIRUS {
		virName = C.GoString(virname)
	} else if ret == C.CL_CLEAN {
		// do nothing
	} else {
		return fmt.Errorf("error scanning file: %s", C.GoString(C.cl_strerror(ret)))
	}
	if len(virName) > 0 {
		return &VirusError{
			VirusName:    virName,
			BytesScanned: uint64(size * C.CL_COUNT_PRECISION),
		}
	}
	return nil
}

func (e *clEngine) Destroy() {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	if e.engine != nil {
		C.cl_engine_free(e.engine)
		e.engine = nil
		e.compiled = 0
	}
}

type VirusError struct {
	VirusName    string
	BytesScanned uint64
}

func (e *VirusError) Error() string {
	return fmt.Sprintf("found virus %s", e.VirusName)
}
