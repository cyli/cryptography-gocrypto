package main

// #include <stdlib.h>
import "C"

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"log"
	"reflect"
	"sync"
	"unsafe"
)

type pointerProxy struct {
	sync.Mutex
	counter int
	cache   map[C.longlong]*refCounter
}

type refCounter struct {
	opaqueObject interface{}
	freeableData []unsafe.Pointer
	refCount     int
}

func (p *pointerProxy) UpRef(id C.longlong) {
	p.Lock()
	if r, ok := p.cache[id]; ok {
		r.refCount++
		log.Printf("upref ID %d to %d\n", id, r.refCount)
	}
	p.Unlock()
}

func (p *pointerProxy) DownRef(id C.longlong) {
	p.Lock()
	if r, ok := p.cache[id]; ok {
		if r.refCount-1 == 0 {
			log.Printf("downref ID %d: no more refs, so deleting\b", id)
			for _, ptr := range r.freeableData {
				log.Printf("\tdownref ID %d: freeing attached data\n", id)
				C.free(ptr)
			}
			delete(p.cache, id)
		} else {
			r.refCount--
			log.Printf("downref ID %d to %d\n", id, r.refCount)
		}
	}
	p.Unlock()
}

func (p *pointerProxy) Cache(ctx interface{}) C.longlong {
	p.Lock()
	p.counter++
	id := C.longlong(p.counter)
	ptrProxy.cache[id] = &refCounter{
		opaqueObject: ctx,
		refCount:     1,
	}
	p.Unlock()
	return id
}

var ptrProxy pointerProxy

func init() {
	ptrProxy = pointerProxy{
		cache: make(map[C.longlong]*refCounter),
	}
}

var supportedHashes = map[string]func() hash.Hash{
	"sha1":   sha1.New,
	"sha224": sha256.New224,
	"sha256": sha256.New,
	"sha384": sha512.New384,
	"sha512": sha512.New,
	"md5":    md5.New,
}

//export IsHashSupported
func IsHashSupported(hashChar *C.char) C.int {
	hashType := C.GoString(hashChar)
	if _, ok := supportedHashes[hashType]; ok {
		return C.int(1)
	}
	return C.int(0)
}

//export CreateHash
func CreateHash(hashChar *C.char) C.longlong {
	hashType := C.GoString(hashChar)
	if hashFactory, ok := supportedHashes[hashType]; ok {
		return ptrProxy.Cache(hashFactory())
	}
	return C.longlong(0)
}

//export UpdateHashOrHMAC
func UpdateHashOrHMAC(id C.longlong, data *C.char, dataLen C.int) C.int {
	if refCounter, ok := ptrProxy.cache[id]; ok {
		if ctx, ok := refCounter.opaqueObject.(hash.Hash); ok {
			goData := C.GoBytes(unsafe.Pointer(data), dataLen)
			ctx.Write(goData)
			return C.int(1)
		}
	}
	return C.int(0)
}

//export FinalizeHashOrHMAC
func FinalizeHashOrHMAC(id C.longlong) *C.char {
	if refCounter, ok := ptrProxy.cache[id]; ok {
		if ctx, ok := refCounter.opaqueObject.(hash.Hash); ok {
			digest := C.CString(string(ctx.Sum(nil)))
			refCounter.freeableData = append(refCounter.freeableData, unsafe.Pointer(digest))
			return digest
		}
	}
	return nil
}

// stolen from https://www.reddit.com/r/golang/comments/3c6z6x/copy_a_hashhash/
func copyHash(src hash.Hash) hash.Hash {
	typ := reflect.TypeOf(src)
	val := reflect.ValueOf(src)
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
		val = val.Elem()
	}
	elem := reflect.New(typ).Elem()
	elem.Set(val)
	return elem.Addr().Interface().(hash.Hash)
}

//export CopyHashOrHMAC
func CopyHashOrHMAC(id C.longlong) C.longlong {
	if refCounter, ok := ptrProxy.cache[id]; ok {
		if ctx, ok := refCounter.opaqueObject.(hash.Hash); ok {
			return ptrProxy.Cache(copyHash(ctx))
		}
	}
	return C.longlong(0)
}

//export CreateHMAC
func CreateHMAC(hashChar *C.char, keyChar *C.char, keyLen C.int) C.longlong {
	key := C.GoBytes(unsafe.Pointer(keyChar), keyLen)
	hashType := C.GoString(hashChar)
	if hashFactory, ok := supportedHashes[hashType]; ok {
		return ptrProxy.Cache(hmac.New(hashFactory, key))
	}
	return C.longlong(0)
}

// type cipherConstructor struct {
// 	blockConstructorTakesKey func([]byte) (cipher.Block, int, error)
// 	blockSize                int
// }

// type blockCipherer struct {
// 	block cipher.Block
// 	iv []byte
// 	encrypt bool

// 	buffer []byte
// }

// var supportedCiphers = map[string]cipherConstructor{
// 	"aes": cipherConstructor{
// 		blockConstructorTakesKey: aes.NewCipher,
// 		blockSize: aes.BlockSize,
// 	},
// 	// "blowfish": blowfish.NewCipher,
// 	// "cast5":    cast5.NewCipher,
// 	// "des":      des.NewCipher,
// }

// var supportedModes = map[string]... {
// 	"cbc":
// }

//export CreateCipher
func CreateCipher(cipherChar *C.char, modeChar *C.char, operation C.int,
	ivChar *C.char, ivLen C.int, keyChar *C.char, keyLen C.int) C.longlong {

	// cipherType := C.GoString(cipherChar)
	// modeType := C.GoString(modeChar)
	iv := C.GoBytes(unsafe.Pointer(ivChar), ivLen)
	key := C.GoBytes(unsafe.Pointer(keyChar), keyLen)

	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return C.longlong(0)
	}

	var ctx cipher.BlockMode
	switch operation {
	case 0:
		ctx = cipher.NewCBCEncrypter(aesBlock, iv)
	default:
		ctx = cipher.NewCBCDecrypter(aesBlock, iv)
	}

	return ptrProxy.Cache(ctx)
}

// assumption is that srcLen is always a multiple of the block size

//export UpdateCipher
func UpdateCipher(id C.longlong, dst *C.char, srcChar *C.char, srcLen C.int) C.int {
	if refCounter, ok := ptrProxy.cache[id]; ok {
		if ctx, ok := refCounter.opaqueObject.(cipher.BlockMode); ok {
			if int(srcLen)%ctx.BlockSize() != 0 {
				log.Fatalf("Passed non-block-aligned data to a block cipher")
			}

			src := C.GoBytes(unsafe.Pointer(srcChar), srcLen)
			ctx.CryptBlocks(src, src)
			cBuf := (*[1 << 30]byte)(unsafe.Pointer(dst))
			copy(cBuf[:], src)
			return C.int(1)
		}
	}
	return C.int(0)
}

//export UpRef
func UpRef(id C.longlong) {
	ptrProxy.UpRef(id)
}

//export DownRef
func DownRef(id C.longlong) {
	ptrProxy.DownRef(id)
}

func main() {}
