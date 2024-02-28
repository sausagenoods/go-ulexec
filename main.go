package main

// #include <sys/auxv.h>
// #include <sys/mman.h>
// #include <string.h>
import "C"
import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"os"
	"runtime/debug"
	"syscall"
	"unsafe"

	"github.com/saferwall/elf"
)

var binaryPath = "/nix/store/9w8x9qzjkiy2jsa4zji31yxjdih92h97-iproute2-6.5.0/bin/ip"
var binaryArgs = "a"

// PT_LOAD entries
type phEntry struct {
	header elf.ELF64ProgramHeader
	data   []byte
}

func main() {
	// Attempt to disable GC
	debug.SetGCPercent(-1)
	debug.SetMemoryLimit(math.MaxInt64)
	binaryBytes, err := os.ReadFile(binaryPath)
	if err != nil {
		log.Fatal("Failed to read binary:", err)
	}
	ELFExec(binaryPath, "-a", binaryBytes)
}

func calculateMapSize(progHeaders []phEntry) uint64 {
	var mapSize uint64 = 0

	for _, h := range progHeaders {
		sum := h.header.Vaddr + h.header.Memsz
		if sum > mapSize {
			mapSize = sum
		}
	}

	// Not PIE
	if progHeaders[0].header.Vaddr != 0x00 {
		adjust := progHeaders[0].header.Vaddr
		log.Printf("Not a PIE binary so adjusting size down with 0x%.8x", adjust)
		mapSize -= adjust
	}

	log.Printf("Total calculated map size for executable is: 0x%.8x", mapSize)
	return mapSize
}

func floor(addr, pageSize uint64) uint64 {
	return addr & (-pageSize)
}

func ceil(addr, pageSize uint64) uint64 {
	return floor(addr+pageSize-1, pageSize)
}

func generateMunmap(addr, length uint64) []byte {
	/* 48 c7 c0 0b 00 00 00    mov    $0xb,%rax
	   48 bf 66 66 66 66 66    movabs $0x6666666666666666,%rdi  ; addr
	   66 66 66
	   48 be 52 52 52 52 42    movabs $0x4242424252525252,%rsi  ; length
	   42 42 42
	   0f 05                   syscall
	*/
	buf := []byte{0x48, 0xc7, 0xc0, 0x0b, 0x00, 0x00, 0x00, 0x48, 0xbf}
	//buf = b"\x48 \xc7  \xc0  \x0b  \x00  \x00  \x00  \x48  \xbf
	buf = binary.LittleEndian.AppendUint64(buf, addr)
	buf = append(buf, []byte{0x48, 0xbe}...)
	buf = binary.LittleEndian.AppendUint64(buf, length)
	buf = append(buf, []byte{0x0f, 0x05}...)
	return buf
}

func generateMmap(addr, length uint64, prot, flags, fd, offset uint32) []byte {
	/* 48 c7 c0 09 00 00 00    mov    $0x9,%rax
	   48 bf 66 66 66 66 66    movabs $0x6666666666666666,%rdi  ; addr
	   66 66 66
	   48 be 52 52 52 52 42    movabs $0x4242424252525252,%rsi  ; length
	   42 42 42
	   48 c7 c2 7b 00 00 00    mov    $0x7b,%rdx     ; prot
	   49 c7 c2 9a 02 00 00    mov    $0x29a,%r10    ; flags
	   49 c7 c0 ff ff ff ff    mov    $0xffffffffffffffff,%r8 ; fd
	   49 c7 c1 00 00 00 00    mov    $0x0,%r9  ; offset
	   0f 05                   syscall
	   50                      push   %rax
	   4c 8b 1c 24             mov    (%rsp),%r11
	*/
	buf := []byte{0x48, 0xc7, 0xc0, 0x09, 0x00, 0x00, 0x00, 0x48, 0xbf}
	buf = binary.LittleEndian.AppendUint64(buf, addr)
	buf = append(buf, []byte{0x48, 0xbe}...)
	buf = binary.LittleEndian.AppendUint64(buf, length)
	buf = append(buf, []byte{0x48, 0xc7, 0xc2}...)
	buf = binary.LittleEndian.AppendUint32(buf, prot)
	buf = append(buf, []byte{0x49, 0xc7, 0xc2}...)
	buf = binary.LittleEndian.AppendUint32(buf, flags)
	buf = append(buf, []byte{0x49, 0xc7, 0xc0}...)
	buf = binary.LittleEndian.AppendUint32(buf, fd)
	buf = append(buf, []byte{0x49, 0xc7, 0xc1}...)
	buf = binary.LittleEndian.AppendUint32(buf, offset)
	buf = append(buf, []byte{0x0f, 0x05, 0x50, 0x4c, 0x8b, 0x1c, 0x24}...)
	log.Printf("Generated mmap call (addr=0x%.8x, length=0x%.8x, prot=0x%x, flags=0x%x)", addr, length, prot, flags)
	return buf
}

func generateMemcpy(off, src, sz uint64) []byte {
	/* 48 be a0 14 88 02 00    movabs $0x28814a0,%rsi
	   00 00 00
	   48 bf 00 00 00 00 00    movabs $0x0,%rdi
	   00 00 00
	   4c 01 df                add    %r11,%rdi
	   48 b9 c8 0f 00 00 00    movabs $0xfc8,%rcx
	   00 00 00
	   f3 a4                   rep movsb %ds:(%rsi),%es:(%rdi)
	*/
	buf := []byte{0x48, 0xbe}
	buf = binary.LittleEndian.AppendUint64(buf, src)
	buf = append(buf, []byte{0x48, 0xbf}...)
	buf = binary.LittleEndian.AppendUint64(buf, off)
	buf = append(buf, []byte{0x4c, 0x01, 0xdf, 0x48, 0xb9}...)
	buf = binary.LittleEndian.AppendUint64(buf, sz)
	buf = append(buf, []byte{0xf3, 0xa4}...)
	log.Printf("Generated memcpy call (dst=%%r11 + 0x%.8x, src=0x%.8x, size=0x%.8x)", off, src, sz)
	return buf
}

func generateAuxvFixup(stackBase, auxvStart, auxvOffset, mapOffset uint64, relative bool) []byte {
	/* 49 be 48 47 46 45 44    movabs $0x4142434445464748,%r14
	   43 42 41
	   4d 01 de                add    %r11,%r14
	   49 bf 11 11 11 11 11    movabs $0x1111111111111111,%r15
	   11 11 11
	   4d 89 37                mov    %r14,(%r15)
	*/
	// write at location within auxv the value %r11 + map_offset
	auxvPtr := stackBase + auxvStart + (auxvOffset << 3)
	buf := []byte{0x49, 0xbe}
	buf = binary.LittleEndian.AppendUint64(buf, mapOffset)
	if relative {
		buf = append(buf, []byte{0x4d, 0x01, 0xde}...)
	}
	buf = append(buf, []byte{0x49, 0xbf}...)
	buf = binary.LittleEndian.AppendUint64(buf, auxvPtr)
	buf = append(buf, []byte{0x4d, 0x89, 0x37}...)
	return buf
}

func generateJumpcode(stackPtr, entryPtr uint64) []byte {
	buf := make([]byte, 0)
	// reset main registers (%rax, %rbx, %rcx, %rdx, %rbp, %rsp, %rsi, %rdi) just to be sure
	regs := []byte{0xc0, 0xdb, 0xc9, 0xd2, 0xed, 0xe4, 0xf6, 0xff}
	for _, r := range regs {
		buf = append(buf, []byte{0x48, 0x31}...)
		buf = append(buf, r)
	}
	buf = append(buf, []byte{0x48, 0xbc}...)
	buf = binary.LittleEndian.AppendUint64(buf, stackPtr)
	buf = append(buf, []byte{0x48, 0xb9}...)
	buf = binary.LittleEndian.AppendUint64(buf, entryPtr)
	buf = append(buf, []byte{0x4c, 0x01, 0xd9, 0x48, 0x31, 0xd2, 0xff, 0xe1}...)
	log.Printf("Jumpbuf with entry %%r11+0x%x and stack: 0x%.16x", entryPtr, stackPtr)
	return buf
}

func generateELFLoader(phEntries []phEntry, pageSize uint64) []byte {
	// Generate ELF loader
	elfLoader := make([]byte, 0)

	addr := phEntries[0].header.Vaddr
	mapSize := calculateMapSize(phEntries)

	addrFloor := floor(addr, pageSize)
	log.Printf("Floor: 0x%.8x", addrFloor)
	mapSizeCeil := ceil(mapSize, pageSize)
	log.Printf("Ceil: 0x%.8x", mapSizeCeil)

	munmapCode := generateMunmap(addrFloor, mapSizeCeil)
	elfLoader = append(elfLoader, munmapCode...)

	mmapCode := generateMmap(addrFloor, mapSizeCeil,
		C.PROT_WRITE|C.PROT_EXEC|C.PROT_READ,
		C.MAP_ANONYMOUS|C.MAP_PRIVATE,
		0xffffffff, 0)
	elfLoader = append(elfLoader, mmapCode...)

	// loop over the PT_LOAD entries, generate the copy code
	for i, h := range phEntries {
		src := uint64(uintptr(unsafe.Pointer(&phEntries[i].data)))
		sz, vaddr := h.header.Filesz, h.header.Vaddr

		// not PIE
		if phEntries[0].header.Vaddr != 0x0 {
			vaddr -= phEntries[0].header.Vaddr
		}
		memcpyCode := generateMemcpy(vaddr, src, sz)
		elfLoader = append(elfLoader, memcpyCode...)
	}
	return elfLoader
}

func prepareJumpbuf(jumpBuffer []byte, pageSize uint64) func() {
	dst, err := syscall.Mmap(-1, 0, int(ceil(uint64(len(jumpBuffer)), pageSize)), C.PROT_WRITE, C.MAP_PRIVATE|C.MAP_ANONYMOUS)
	if err != nil {
		log.Fatal("prepareJumpbuf failed to mmap: ", err)
	}
	dstPtr := unsafe.Pointer(&dst[0])
	src := C.CBytes(jumpBuffer)
	log.Printf("Memmove(0x%.8x, 0x%.8x, 0x%.8x)", dstPtr, src, len(jumpBuffer))
	C.memmove(dstPtr, src, C.ulong(len(jumpBuffer)))
	floored := floor(uint64(uintptr(dstPtr)), pageSize)
	ret := C.mprotect(unsafe.Pointer(uintptr(floored)), C.ulong(ceil(uint64(len(jumpBuffer)), pageSize)), C.PROT_READ|C.PROT_EXEC)
	if ret == -1 {
		log.Fatal("Calling mprotect() on jumpbuffer failed")
	}
	return *(*func())(dstPtr)
}

func ELFExec(binaryPath, binaryArgs string, binaryBytes []byte) {
	_ = binaryPath

	p, err := elf.NewBytes(binaryBytes)
	defer p.CloseFile()
	if err != nil {
		panic(err)
	}
	err = p.Parse()
	if err != nil {
		panic(err)
	}

	binReader := bytes.NewReader(binaryBytes)

	// PATH to ld.so in dynamic bins
	interpreterPath := ""

	progHeaders := p.F.ELFBin64.ProgramHeaders64
	phnum := p.F.ELFBin64.Header64.Phnum
	phentsize := p.F.ELFBin64.Header64.Phentsize

	phEntries := make([]phEntry, 0)

	for _, h := range progHeaders {
		if h.Type == uint32(elf.PT_INTERP) {
			fmt.Println("type PT_INTERP")
			interp := make([]byte, h.Filesz)
			n, err := binReader.ReadAt(interp, int64(h.Off))
			if err != nil {
				log.Fatal("failed to read intrp section", err)
			}
			interpreterPath = string(interp[:n-1])
		} else if h.Type == uint32(elf.PT_LOAD) {
			fmt.Println("type PT_LOAD")
			data := make([]byte, h.Filesz)
			_, err := binReader.ReadAt(data, int64(h.Off))
			if err != nil {
				log.Fatal("failed to read PT_LOAD section", err)
			}
			phEntries = append(phEntries, phEntry{header: h, data: data})
		} else {
			fmt.Printf("something else %d\n", h.Type)
		}
	}

	interpreterBytes, err := os.ReadFile(interpreterPath)
	if err != nil {
		log.Fatal("Failed to read interpreter:", err)
	}

	// Construct a stack
	pageSize := syscall.Getpagesize()
	numPages := 2048
	stackSize := numPages * pageSize

	stackBase, err := syscall.Mmap(-1, 0, stackSize,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_ANONYMOUS|syscall.MAP_PRIVATE|syscall.MAP_GROWSDOWN)
	if err != nil {
		log.Fatal("Failed to mmap stack:", err)
	}
	// No need to memset to 0 because of Go's GC it will be zeroed.

	// Setup stack, copy argv and env vars
	// Adjust start of the stack
	stackOffset := stackSize - pageSize
	stackPtr := (*C.size_t)(unsafe.Pointer(&stackBase[stackOffset]))
	log.Printf("Stack allocated at: %p", stackPtr)

	// First item of argv is argc.
	argv := []string{binaryPath, binaryArgs}
	argc := len(argv)

	*stackPtr = C.size_t(argc)

	// Fast forward 1 size_t (8 bytes) since we wrote argc
	ptrPos := 1
	refPos := 0

	// Go strings aren't NULL terminated. Prepare C strings.
	// Also store them in a slice to ensure Go doesn't GC them.
	refs := make([]*C.char, 0)

	// Write rest of argv.
	for _, arg := range argv {
		refs = append(refs, C.CString(arg))
		stackPtr = (*C.size_t)(unsafe.Pointer(&stackBase[stackOffset+ptrPos*int(unsafe.Sizeof(C.size_t(1)))]))
		refPtr := uintptr(unsafe.Pointer(&refs[refPos]))
		*stackPtr = C.size_t(refPtr)
		log.Printf("Pushed 0x%.16x onto stack", refPtr)
		ptrPos++
		refPos++
	}

	// Argv is NULL terminated.
	*(*C.size_t)(unsafe.Pointer(&stackBase[stackOffset+ptrPos*int(unsafe.Sizeof(C.size_t(1)))])) = C.size_t(0)
	ptrPos++

	// Push envp into stack.
	envp := os.Environ()
	for _, e := range envp {
		refs = append(refs, C.CString(e))
		stackPtr = (*C.size_t)(unsafe.Pointer(&stackBase[stackOffset+ptrPos*int(unsafe.Sizeof(C.size_t(1)))]))
		refPtr := uintptr(unsafe.Pointer(&refs[refPos]))
		*stackPtr = C.size_t(refPtr)
		log.Printf("Pushed 0x%.16x onto stack", refPtr)
		log.Printf("Stack: 0x%.16x", stackPtr)
		ptrPos++
		refPos++
	}

	// Envp is NULL terminated
	*(*C.size_t)(unsafe.Pointer(&stackBase[stackOffset+ptrPos*int(unsafe.Sizeof(C.size_t(1)))])) = C.size_t(0)
	ptrPos++

	// Prepare auxv
	auxvOffset := uint64(uintptr(unsafe.Pointer(&stackBase[stackOffset+ptrPos*int(unsafe.Sizeof(C.size_t(1)))])))
	auxvStart := auxvOffset << 3

	// Address pointing to start off auxv
	auxvPtr := C.size_t(uintptr(unsafe.Pointer(&stackBase[stackOffset+ptrPos*int(unsafe.Sizeof(C.size_t(1)))])))

	at_sysinfo_ehdr := C.getauxval(C.AT_SYSINFO_EHDR)
	at_sysinfo := C.getauxval(C.AT_SYSINFO)
	log.Printf("vDSO loaded at 0x%.8x (Auxv entry AT_SYSINFO_EHDR), AT_SYSINFO: 0x%.8x", at_sysinfo_ehdr, at_sysinfo)

	at_clktck := C.getauxval(C.AT_CLKTCK)
	at_hwcap := C.getauxval(C.AT_HWCAP)
	at_hwcap2 := C.getauxval(C.AT_HWCAP2)
	log.Printf("Auxv entries: HWCAP=0x%.8x, HWCAP2=0x%.8x, AT_CLKTCK=0x%.8x",
		at_hwcap, at_hwcap2, at_clktck)

	platform := C.CString("x86_64")
	refs = append(refs, platform)
	at_platform := C.size_t(uintptr(unsafe.Pointer(&platform)))

	// the first reference is argv[0] which is the pathname used to execute the binary
	at_execfn := C.size_t(uintptr(unsafe.Pointer(&refs[0])))

	type auxvEntry struct {
		constName C.size_t
		val       C.size_t
	}

	auxv := make([]*auxvEntry, 0)
	auxv = append(auxv, &auxvEntry{C.AT_BASE, 0x0})
	auxv = append(auxv, &auxvEntry{C.AT_PHDR, 0x0})
	auxv = append(auxv, &auxvEntry{C.AT_ENTRY, 0x0})
	auxv = append(auxv, &auxvEntry{C.AT_PHNUM, C.size_t(phnum)})
	auxv = append(auxv, &auxvEntry{C.AT_PHENT, C.size_t(phentsize)})
	auxv = append(auxv, &auxvEntry{C.AT_PAGESZ, C.size_t(pageSize)})
	auxv = append(auxv, &auxvEntry{C.AT_SECURE, 0})
	auxv = append(auxv, &auxvEntry{C.AT_RANDOM, auxvPtr}) // points to start of auxv // TODO: really?
	auxv = append(auxv, &auxvEntry{C.AT_SYSINFO, at_sysinfo})
	auxv = append(auxv, &auxvEntry{C.AT_SYSINFO_EHDR, at_sysinfo_ehdr})
	auxv = append(auxv, &auxvEntry{C.AT_PLATFORM, at_platform})
	auxv = append(auxv, &auxvEntry{C.AT_EXECFN, at_execfn})
	auxv = append(auxv, &auxvEntry{C.AT_UID, C.size_t(os.Getuid())})
	auxv = append(auxv, &auxvEntry{C.AT_EUID, C.size_t(os.Geteuid())})
	auxv = append(auxv, &auxvEntry{C.AT_GID, C.size_t(os.Getgid())})
	auxv = append(auxv, &auxvEntry{C.AT_EGID, C.size_t(os.Getegid())})

	if at_clktck != 0 {
		auxv = append(auxv, &auxvEntry{C.AT_CLKTCK, C.size_t(at_clktck)})
	}
	if at_hwcap != 0 {
		auxv = append(auxv, &auxvEntry{C.AT_HWCAP, C.size_t(at_hwcap)})
	}
	if at_hwcap2 != 0 {
		auxv = append(auxv, &auxvEntry{C.AT_HWCAP2, C.size_t(at_hwcap2)})
	}

	// auxv is NULL terminated
	auxv = append(auxv, &auxvEntry{C.AT_NULL, C.size_t(0)})

	for _, a := range auxv {
		stackPtr = (*C.size_t)(unsafe.Pointer(&stackBase[stackOffset+ptrPos*int(unsafe.Sizeof(C.size_t(1)))]))
		*stackPtr = a.constName
		ptrPos++
		stackPtr = (*C.size_t)(unsafe.Pointer(&stackBase[stackOffset+ptrPos*int(unsafe.Sizeof(C.size_t(1)))]))
		*stackPtr = a.val
		ptrPos++
	}

	// Build jump buffer

	// TODO: avoid []byte, use []C.size_t

	// Generate ELF loader for executable
	exeLoader := generateELFLoader(phEntries, uint64(pageSize))

	// Done generating elf loader
	jumpBuffer := make([]byte, 0)
	jumpBuffer = append(jumpBuffer, exeLoader...)

	var OFFSET_AT_BASE uint64 = 1
	var OFFSET_AT_PHDR uint64 = 3
	var OFFSET_AT_ENTRY uint64 = 5

	stackBasePtr := uint64(uintptr(unsafe.Pointer(&stackBase[stackOffset])))
	auxvFixup := generateAuxvFixup(stackBasePtr, auxvStart, OFFSET_AT_PHDR, p.F.ELFBin64.Header64.Phoff, true)
	jumpBuffer = append(jumpBuffer, auxvFixup...)
	auxvFixup = generateAuxvFixup(stackBasePtr, auxvStart, OFFSET_AT_ENTRY, p.F.ELFBin64.Header64.Entry, false)
	jumpBuffer = append(jumpBuffer, auxvFixup...)

	// Parse and load interpreter
	ip, err := elf.NewBytes(interpreterBytes)
	defer p.CloseFile()
	if err != nil {
		panic(err)
	}
	err = ip.Parse()
	if err != nil {
		panic(err)
	}

	ipReader := bytes.NewReader(interpreterBytes)
	ipEntries := make([]phEntry, 0)
	for _, h := range ip.F.ELFBin64.ProgramHeaders64 {
		if h.Type == uint32(elf.PT_LOAD) {
			fmt.Println("type PT_LOAD")
			data := make([]byte, h.Filesz)
			_, err := ipReader.ReadAt(data, int64(h.Off))
			if err != nil {
				log.Fatal("failed to read PT_LOAD section", err)
			}
			ipEntries = append(ipEntries, phEntry{header: h, data: data})
		}
	}

	ipLoader := generateELFLoader(phEntries, uint64(pageSize))
	jumpBuffer = append(jumpBuffer, ipLoader...)
	ipFixup := generateAuxvFixup(stackBasePtr, auxvStart, OFFSET_AT_BASE, 0, true)
	jumpBuffer = append(jumpBuffer, ipFixup...)
	entryPoint := ip.F.ELFBin64.Header64.Entry
	log.Printf("Generating jumpcode with entry_point=0x%.8x and stack=0x%.8x", entryPoint, stackBasePtr)

	jc := generateJumpcode(stackBasePtr, entryPoint)
	jumpBuffer = append(jumpBuffer, jc...)

	jumpfunc := prepareJumpbuf(jumpBuffer, uint64(pageSize))
	jumpfunc()

	/*
	   f, err := os.Create("file.bin")

	   	if err != nil {
	   		log.Fatal("Couldn't open file")
	   	}

	   defer f.Close()

	   _, err = f.Write(jumpBuffer)

	   	if err != nil {
	   		fmt.Println("Error:", err)
	   		return
	   	}

	   log.Printf("%v", jumpBuffer)
	*/
}
