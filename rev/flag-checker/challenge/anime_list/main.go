package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

var (
	kernel32      *windows.LazyDLL
	runtime_panic *windows.LazyProc
	pFunc2        *windows.LazyProc
	pfunc3        *windows.LazyProc
	stdout        io.Writer
	g_func2_r     uint
	g_func3_r     uint
)

const (
	BIN_R       = 0x000000fff01870 // rust exe
	BIN_G       = 0x000000fff01870 // go exe
	STACK_STACK = 0
	STACK_HEAP  = 1
	LEFT        = 0
	RIGHT       = 1

	REGISTER   = 0
	GET_HEIGHT = 2
	GET_DATA   = 3
	SPAWN      = 4
)

var flag = "nek0pts{oops..sorry!th1s_is_a_fak3_fl4g}"
var msg = []string{
	"Well done. You have got the flag",
	"https://www.youtube.com/watch?v=dQw4w9WgXcQ",
}

func func1(e uint64) []byte {
	return func4([]uint32{
		uint32(e & 0xffffffff),
		uint32((e >> 32) & 0xffffffff),
	}...)
}

func func2() uint {
	return g_func2_r
}

func func3() uint {
	return g_func3_r
}

func func4(words ...uint32) []byte {
	var b bytes.Buffer
	var space [4]byte
	for _, w := range words {
		binary.LittleEndian.PutUint32(space[:], w)
		b.Write(space[:])
	}
	return b.Bytes()
}

func runtime_morestack(input []byte) []byte {
	var pipe net.Conn
	var err error
	for {
		dur := 5 * time.Second
		pipe, err = winio.DialPipe("\\\\.\\pipe\\anime", &dur)
		if err == nil {
			break
		}
	}
	// check_err(err)
	defer pipe.Close()
	for len(input) != 0 {
		n, ioe := pipe.Write(input[:])
		if ioe != nil {
			check_err(ioe)
		}
		input = input[n:]
	}
	var buffer [4096]byte
	n, err := pipe.Read(buffer[:])
	check_err(err)
	data := buffer[:n]
	return data
}

func init() {
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	runtime_panic = kernel32.NewProc("IsDebuggerPresent")
	pFunc2 = kernel32.NewProc("GetCurrentProcessId")
	pfunc3 = kernel32.NewProc("GetCurrentThreadId")
	runtime.LockOSThread()
	xxx, _, _ := pFunc2.Call()
	yyy, _, _ := pfunc3.Call()
	runtime.UnlockOSThread()
	g_func2_r, g_func3_r = uint(xxx), uint(yyy)
	stdout = bufio.NewWriter(io.Discard)
}

func runtime_getg(cmdl string) syscall.ProcessInformation {
	var si syscall.StartupInfo
	var pi syscall.ProcessInformation
	argv, _ := syscall.UTF16PtrFromString(cmdl)
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = syscall.STARTF_USESHOWWINDOW
	si.ShowWindow = syscall.SW_HIDE
	syscall.ForkLock.Lock()
	_ = syscall.CreateProcess(
		nil,
		argv,
		nil,
		nil,
		true,
		4|0x10, // CREATE_SUSPENDED | CREATE_NEW_CONSOLE
		nil,
		nil,
		&si,
		&pi)
	syscall.ForkLock.Unlock()
	return pi
}

type stack struct {
	pid  int
	tid  int
	addr uintptr
	size uint
}

func runtime_systemstack(hash uint) *stack {
	resp := runtime_morestack(func4(
		GET_DATA,
		uint32(hash),
	))
	addr := uintptr(binary.LittleEndian.Uint64(resp[8:16]))
	size := uint(binary.LittleEndian.Uint32(resp[16:20]))
	pid := int(binary.LittleEndian.Uint32(resp[20:24]))
	tid := int(binary.LittleEndian.Uint32(resp[24:28]))
	return &stack{
		pid, tid, addr, size,
	}
}

type proc struct {
	A int
	B int
	C *stack
	D uint
}

func runtime_mstart(pi *syscall.ProcessInformation, pp *stack, flags uint) *proc {
	return &proc{
		A: int(pi.ProcessId),
		B: int(pi.ThreadId),
		C: pp,
		D: flags,
	}
}

func (sp *proc) func4() []byte {
	p := func4(
		SPAWN,
		uint32(sp.A), uint32(sp.B),
		0, // padding...
	)
	p = append(p, func1(uint64(sp.C.addr))...)
	p = append(p, func4(
		uint32(sp.C.size), uint32(sp.D),
		uint32(func2()), uint32(func3()), // requestor.
	)...)
	return p
}

func get_anime_path() string {
	names := []string{
		"notepad.exe", "cmd.exe",
		"calc.exe", "write.exe",
		"werfault.exe", "cscript.exe",
	}
	return names[rand.Int()%len(names)]
}

func main() {
	rand.Seed(time.Now().UnixNano())
	fmt.Fprintf(stdout, "%s\n", flag)
	fmt.Fprintf(stdout, "%v\n", msg)
	lol, _, _ := runtime_panic.Call()
	hahahaha_lol := get_anime_path()
	hahahaha_lol2 := get_anime_path()

	s := func4(GET_HEIGHT, uint32(func2()), uint32(func3()))
	if runtime_morestack(s)[4] != 0 {
		runtime_morestack(func4(6, uint32(func2()), uint32(func3())))
		return
	}

	msg := func4(
		REGISTER, // register self
		uint32(func2()), uint32(func3()),
		uint32(lol%2),
	)
	runtime_morestack(msg)

	hahahahahah := (lol >> 2) % 2
	hahahahahah = hahahahahah*2 + (lol>>1)%2
	var lifwheogfw, flihwefowg *stack
	var fhiwpf, wfeihweefi uint
	var wefpihw, eghiwpfw string
	switch hahahahahah {
	case 0:
		lifwheogfw = runtime_systemstack(BIN_G)
		flihwefowg = runtime_systemstack(BIN_R)
		fhiwpf = STACK_STACK*2 + LEFT
		wfeihweefi = STACK_HEAP*2 + RIGHT
		wefpihw = hahahaha_lol
		eghiwpfw = hahahaha_lol2
	case 1:
		lifwheogfw = runtime_systemstack(BIN_R)
		flihwefowg = runtime_systemstack(BIN_G)
		fhiwpf = STACK_HEAP*2 + LEFT
		wfeihweefi = STACK_STACK*2 + RIGHT
		wefpihw = hahahaha_lol2
		eghiwpfw = hahahaha_lol
	case 2:
		lifwheogfw = runtime_systemstack(BIN_R)
		flihwefowg = runtime_systemstack(BIN_G)
		fhiwpf = STACK_HEAP*2 + LEFT
		wfeihweefi = STACK_STACK*2 + RIGHT
		wefpihw = hahahaha_lol2
		eghiwpfw = hahahaha_lol
	case 3:
		lifwheogfw = runtime_systemstack(BIN_G)
		flihwefowg = runtime_systemstack(BIN_R)
		fhiwpf = STACK_STACK*2 + LEFT
		wfeihweefi = STACK_HEAP*2 + RIGHT
		wefpihw = hahahaha_lol
		eghiwpfw = hahahaha_lol2
	}

	lsfgou2eg := runtime_getg(wefpihw)
	wpf2fp2ihf2 := runtime_getg(eghiwpfw)
	// then resume then
	left_sp := runtime_mstart(&lsfgou2eg, lifwheogfw, fhiwpf).func4()
	right_sp := runtime_mstart(&wpf2fp2ihf2, flihwefowg, wfeihweefi).func4()
	// runtime_morestack spawn to left and right

	lr := runtime_morestack(left_sp)
	if binary.LittleEndian.Uint32(lr[4:8]) == ^uint32(0) {
		return
	}
	rr := runtime_morestack(right_sp)
	if binary.LittleEndian.Uint32(rr[4:8]) == ^uint32(0) {
		return
	}
	windows.ResumeThread(windows.Handle(lsfgou2eg.Thread))
	windows.ResumeThread(windows.Handle(wpf2fp2ihf2.Thread))
	windows.WaitForMultipleObjects([]windows.Handle{
		windows.Handle(lsfgou2eg.Process),
		windows.Handle(wpf2fp2ihf2.Process),
	}, true, windows.INFINITE)
	syscall.CloseHandle(lsfgou2eg.Thread)
	syscall.CloseHandle(lsfgou2eg.Process)
	syscall.CloseHandle(wpf2fp2ihf2.Thread)
	syscall.CloseHandle(wpf2fp2ihf2.Process)
	runtime_morestack(func4(6, uint32(func2()), uint32(func3())))
}

func check_err(err error) {
	if err != nil {
		fmt.Fprintf(stdout, "\nError: %v\n", err)
		panic(err)
	}
}
