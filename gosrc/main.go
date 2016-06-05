package main

// #include <stdlib.h>
import "C"

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
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

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"
)

// memory management hack; cryptography API requires updating existing hashes,
// HMACs, and ciphers, so we need to cache them so they don't get GCed while
// Python might still be referencing it

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
			log.Printf("downref ID %d: no more refs, so deleting, and freeing %d data\n", id, len(r.freeableData))
			for _, ptr := range r.freeableData {
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
	ptrProxy().cache[id] = &refCounter{
		opaqueObject: ctx,
		refCount:     1,
	}
	p.Unlock()
	return id
}

var _ptrProxy *pointerProxy

func ptrProxy() *pointerProxy {
	if _ptrProxy == nil {
		_ptrProxy = &pointerProxy{
			cache: make(map[C.longlong]*refCounter),
		}
	}
	return _ptrProxy
}

// ----- Hashes and HMAC support -----

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
		return ptrProxy().Cache(hashFactory())
	}
	return C.longlong(-1)
}

//export UpdateHashOrHMAC
func UpdateHashOrHMAC(id C.longlong, data *C.char, dataLen C.int) C.int {
	if refCounter, ok := ptrProxy().cache[id]; ok {
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
	if refCounter, ok := ptrProxy().cache[id]; ok {
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
	if refCounter, ok := ptrProxy().cache[id]; ok {
		if ctx, ok := refCounter.opaqueObject.(hash.Hash); ok {
			return ptrProxy().Cache(copyHash(ctx))
		}
	}
	return C.longlong(0)
}

//export CreateHMAC
func CreateHMAC(hashChar *C.char, keyChar *C.char, keyLen C.int) C.longlong {
	key := C.GoBytes(unsafe.Pointer(keyChar), keyLen)
	hashType := C.GoString(hashChar)
	if hashFactory, ok := supportedHashes[hashType]; ok {
		return ptrProxy().Cache(hmac.New(hashFactory, key))
	}
	return C.longlong(-1)
}

// ----- Cipher support -----

var supportedBlockCiphers = map[string]func([]byte) (cipher.Block, error){
	"aes":  aes.NewCipher,
	"3des": des.NewTripleDESCipher,
	"blowfish": func(key []byte) (cipher.Block, error) {
		c, err := blowfish.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return c, nil
	},
	"cast5": func(key []byte) (cipher.Block, error) {
		c, err := cast5.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return c, nil
	},
}

type cipherer struct {
	block   cipher.Block
	updater func(a, b []byte)
}

var supportedBlockModes = map[string]func(cipher.Block, []byte, C.int) cipherer{
	"ecb": func(b cipher.Block, _ []byte, operation C.int) cipherer {
		// just pipe things directly into the block
		if operation == 0 {
			return cipherer{block: b, updater: b.Decrypt}
		}
		return cipherer{block: b, updater: b.Encrypt}
	},
	"cbc": func(b cipher.Block, iv []byte, operation C.int) cipherer {
		c := cipherer{block: b}
		switch operation {
		case 0:
			c.updater = cipher.NewCBCDecrypter(b, iv).CryptBlocks
		default:
			c.updater = cipher.NewCBCEncrypter(b, iv).CryptBlocks
		}
		return c
	},
	// "ctr": func(b cipher.Block, iv []byte, _ C.int) cipherer {
	// 	return cipherer{block: b, updater: cipher.NewCTR(b, iv).XORKeyStream}
	// },
}

//export IsCipherSupported
func IsCipherSupported(cipherChar *C.char, modeChar *C.char) C.int {
	cipherType := C.GoString(cipherChar)
	modeType := C.GoString(modeChar)
	_, cipherSupported := supportedBlockCiphers[cipherType]
	_, modeSupported := supportedBlockModes[modeType]

	if cipherSupported && modeSupported {
		return C.int(1)
	}
	return C.int(0)
}

//export CreateCipher
func CreateCipher(cipherChar *C.char, modeChar *C.char, operation C.int,
	ivChar *C.char, ivLen C.int, keyChar *C.char, keyLen C.int) C.longlong {
	// we are counting 0 as decryption, 1 as encryption (alphabetical)

	cipherType := C.GoString(cipherChar)
	modeType := C.GoString(modeChar)
	iv := C.GoBytes(unsafe.Pointer(ivChar), ivLen)
	key := C.GoBytes(unsafe.Pointer(keyChar), keyLen)

	blockFactory, ok := supportedBlockCiphers[cipherType]
	if !ok {
		return C.longlong(-1)
	}
	block, err := blockFactory(key)
	if err != nil {
		log.Printf("Creating block cipher %s with key len %d failed: %v\n", cipherType, keyLen, err)
		return C.longlong(-1)
	}

	modeFactory, ok := supportedBlockModes[modeType]
	if !ok {
		return C.longlong(-1)
	}
	return ptrProxy().Cache(modeFactory(block, iv, operation))
}

// assumption is that srcLen is always a multiple of the block size

//export UpdateCipher
func UpdateCipher(id C.longlong, dst *C.char, srcChar *C.char, srcLen C.int) C.int {
	if refCounter, ok := ptrProxy().cache[id]; ok {
		if ctx, ok := refCounter.opaqueObject.(cipherer); ok {
			if int(srcLen)%ctx.block.BlockSize() != 0 {
				log.Fatalf("Passed non-block-aligned data to a block cipher")
			}

			src := C.GoBytes(unsafe.Pointer(srcChar), srcLen)
			// update in blocks of BlockSize
			for i := 0; i < int(srcLen); i += ctx.block.BlockSize() {
				chunk := src[i : i+ctx.block.BlockSize()]
				ctx.updater(chunk, chunk)
			}
			cBuf := (*[1 << 30]byte)(unsafe.Pointer(dst))
			copy(cBuf[:], src)
			return C.int(1)
		}
	}
	return C.int(0)
}

//export UpRef
func UpRef(id C.longlong) {
	ptrProxy().UpRef(id)
}

//export DownRef
func DownRef(id C.longlong) {
	ptrProxy().DownRef(id)
}

func main() {}
