package main

// #include <stdlib.h>
import "C"

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"log"
	"sync"
	"unsafe"
)

type charStruct struct {
	data *C.char
}

type pointerProxy struct {
	sync.Mutex
	cache map[int]*refCounter
}

type refCounter struct {
	opaqueObject interface{}
	freeableData []unsafe.Pointer
	refCount     int
}

func (p *pointerProxy) UpRef(id int) {
	if r, ok := p.cache[id]; ok {
		r.refCount += 1
		log.Println("upref", r.refCount)
	}
}

func (p *pointerProxy) DownRef(id int) {
	if r, ok := p.cache[id]; ok {
		if r.refCount-1 == 0 {
			log.Println("downref deleting")
			for _, ptr := range r.freeableData {
				log.Println("deleting some data")
				C.free(ptr)
			}
			delete(p.cache, id)
		} else {
			log.Println("downref not deleting", r.refCount)
			r.refCount -= 1
		}
	}
}

var ptrProxy pointerProxy

//export CreateHash
func CreateHash(hashChar *C.char) int {
	var h hash.Hash

	hashType := C.GoString(hashChar)
	switch hashType {
	case "sha1":
		h = sha1.New()
	case "sha224":
		h = sha256.New224()
	case "sha256":
		h = sha256.New()
	case "sha384":
		h = sha512.New384()
	case "sha512":
		h = sha512.New()
	case "md5":
		h = md5.New()
	default:
		return 0
	}
	if ptrProxy.cache == nil {
		ptrProxy = pointerProxy{
			cache: make(map[int]*refCounter),
		}
	}
	key := (*int)(unsafe.Pointer(&h))
	ptrProxy.cache[*key] = &refCounter{
		opaqueObject: h,
		refCount:     1,
	}
	return *key
}

//export UpdateHash
func UpdateHash(h int, data *C.char, size C.int) int {
	if refCounter, ok := ptrProxy.cache[h]; ok {
		if hasher, ok := refCounter.opaqueObject.(hash.Hash); ok {
			bytes := C.GoBytes(unsafe.Pointer(data), size)
			hasher.Write(bytes)
			return 1
		}
	}
	return 0
}

//export FinalizeHash
func FinalizeHash(h int) *C.char {
	if refCounter, ok := ptrProxy.cache[h]; ok {
		if hasher, ok := refCounter.opaqueObject.(hash.Hash); ok {
			digest := C.CString(string(hasher.Sum(nil)))
			refCounter.freeableData = append(refCounter.freeableData, unsafe.Pointer(digest))

			return digest
		}
	}
	return nil
}

//export CreateHMAC
func CreateHMAC(hashChar *C.char, keyChar *C.char, keyLen C.int) int {
	var h func() hash.Hash

	key := C.GoBytes(unsafe.Pointer(keyChar), keyLen)

	hashType := C.GoString(hashChar)
	switch hashType {
	case "sha1":
		h = sha1.New
	case "sha224":
		h = sha256.New224
	case "sha256":
		h = sha256.New
	case "sha384":
		h = sha512.New384
	case "sha512":
		h = sha512.New
	case "md5":
		h = md5.New
	default:
		return 0
	}
	ctx := hmac.New(h, key)
	if ptrProxy.cache == nil {
		ptrProxy = pointerProxy{
			cache: make(map[int]*refCounter),
		}
	}
	mapKey := (*int)(unsafe.Pointer(&ctx))
	ptrProxy.cache[*mapKey] = &refCounter{
		opaqueObject: ctx,
		refCount:     1,
	}
	return *mapKey
}

//export UpdateHMAC
func UpdateHMAC(id int, data *C.char, dataLen C.int) {
	if refCounter, ok := ptrProxy.cache[id]; ok {
		if ctx, ok := refCounter.opaqueObject.(hash.Hash); ok {
			goData := C.GoBytes(unsafe.Pointer(data), dataLen)
			ctx.Write(goData)
		}
	}
}

//export FinalizeHMAC
func FinalizeHMAC(id int) *C.char {
	if refCounter, ok := ptrProxy.cache[id]; ok {
		if ctx, ok := refCounter.opaqueObject.(hash.Hash); ok {
			digest := C.CString(string(ctx.Sum(nil)))
			refCounter.freeableData = append(refCounter.freeableData, unsafe.Pointer(digest))
			return digest
		}
	}
	return nil
}

//export UpRef
func UpRef(id int) {
	ptrProxy.UpRef(id)
}

//export DownRef
func DownRef(id int) {
	ptrProxy.DownRef(id)
}

func main() {}
