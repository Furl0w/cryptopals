package cryptochallenges

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"strings"
)

func seekAndAppendNewtext(ciphertext []byte, nonce []byte, block cipher.Block, offset int, newtext []byte) []byte {
	plaintext := encryptCTR(ciphertext, nonce, block)[:offset]
	plaintext = append(plaintext, newtext...)
	return encryptCTR(plaintext, nonce, block)
}

//So obviously I did it straight forward with an offset of 0 replacing the whole plaintext
//If the offset was limited a simple for loop starting with the max len of the offset edited at each time
//would do the trick by allowing the recovery of the keystream in the same way

func attackSeekCTR(cipher []byte, nonce []byte, block cipher.Block) []byte {
	input := strings.Repeat("A", len(cipher))
	generatedCipher := seekAndAppendNewtext(cipher, nonce, block, 0, []byte(input))
	keystream := make([]byte, len(input))
	for i := range input {
		keystream[i] = input[i] ^ generatedCipher[i]
	}
	plaintext := make([]byte, len(cipher))
	for i := range cipher {
		plaintext[i] = cipher[i] ^ keystream[i]
	}
	return plaintext
}

func concatAndEncryptCTR(prefix string, userdata string, suffix string, nonce []byte, block cipher.Block) []byte {
	userdata = strings.Map(func(r rune) rune {
		if r == rune('=') || r == rune(';') {
			return -1
		}
		return r
	}, userdata)
	query := prefix + userdata + suffix
	return encryptCTR([]byte(query), nonce, block)
}

//comment1=cooking %20MCs;userdata= AAAAAAadminAtrue ;comment2=%20like%20a%20pound%20of%20bacon
//Flip 5 and 11 from second block, A to ; and A to =
func makeAdminCTR(prefix string, suffix string, nonce []byte, block cipher.Block) string {
	encrypted := concatAndEncryptCTR(prefix, "AAAAAAadminAtrue", suffix, nonce, block)
	encrypted[block.BlockSize()*2+5] = encrypted[block.BlockSize()*2+5] ^ byte('A') ^ byte(';')
	encrypted[block.BlockSize()*2+11] = encrypted[block.BlockSize()*2+11] ^ byte('A') ^ byte('=')
	decrypted := string(encryptCTR(encrypted, nonce, block))
	return decrypted
}

//Implementation of sha1 from the crypto library

const sha1Size = 20

const sha1BlockSize = 64

const (
	chunk = 64
	init0 = 0x67452301
	init1 = 0xEFCDAB89
	init2 = 0x98BADCFE
	init3 = 0x10325476
	init4 = 0xC3D2E1F0
)

type digest struct {
	h   [5]uint32
	x   [chunk]byte
	nx  int
	len uint64
}

func (d *digest) Reset() {
	d.h[0] = init0
	d.h[1] = init1
	d.h[2] = init2
	d.h[3] = init3
	d.h[4] = init4
	d.nx = 0
	d.len = 0
}

//For length extension attack
func (d *digest) ResetCustom(IV []uint32) {
	d.h[0] = IV[0]
	d.h[1] = IV[1]
	d.h[2] = IV[2]
	d.h[3] = IV[3]
	d.h[4] = IV[4]
	d.nx = 0
	d.len = 0
}

func (d *digest) Size() int      { return sha1Size }
func (d *digest) BlockSize() int { return sha1BlockSize }

func sha1New() *digest {
	d := new(digest)
	d.Reset()
	return d
}

func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == chunk {
			sha1Block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= chunk {
		n := len(p) &^ (chunk - 1)
		sha1Block(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return

}

func (d *digest) Sum(in []byte) []byte {
	d0 := *d
	hash := d0.checkSum()
	return append(in, hash[:]...)

}

func (d *digest) checkSum() [sha1Size]byte {
	len := d.len
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		d.Write(tmp[0 : 56-len%64])
	} else {
		d.Write(tmp[0 : 64+56-len%64])
	}
	// Length in bits.
	len <<= 3
	putUint64(tmp[:], len)
	d.Write(tmp[0:8])
	if d.nx != 0 {
		panic("d.nx != 0")
	}
	var digest [sha1Size]byte
	putUint32(digest[0:], d.h[0])
	putUint32(digest[4:], d.h[1])
	putUint32(digest[8:], d.h[2])
	putUint32(digest[12:], d.h[3])
	putUint32(digest[16:], d.h[4])
	return digest
}

func sha1Sum(data []byte) [sha1Size]byte {
	var d digest
	d.Reset()
	d.Write(data)
	return d.checkSum()
}

func putUint64(x []byte, s uint64) {
	_ = x[7]
	x[0] = byte(s >> 56)
	x[1] = byte(s >> 48)
	x[2] = byte(s >> 40)
	x[3] = byte(s >> 32)
	x[4] = byte(s >> 24)
	x[5] = byte(s >> 16)
	x[6] = byte(s >> 8)
	x[7] = byte(s)
}

func putUint32(x []byte, s uint32) {
	_ = x[3]
	x[0] = byte(s >> 24)
	x[1] = byte(s >> 16)
	x[2] = byte(s >> 8)
	x[3] = byte(s)
}

const (
	_K0 = 0x5A827999
	_K1 = 0x6ED9EBA1
	_K2 = 0x8F1BBCDC
	_K3 = 0xCA62C1D6
)

func sha1Block(dig *digest, p []byte) {
	var w [16]uint32
	h0, h1, h2, h3, h4 := dig.h[0], dig.h[1], dig.h[2], dig.h[3], dig.h[4]
	for len(p) >= chunk {
		for i := 0; i < 16; i++ {
			j := i * 4
			w[i] = uint32(p[j])<<24 | uint32(p[j+1])<<16 | uint32(p[j+2])<<8 | uint32(p[j+3])
		}
		a, b, c, d, e := h0, h1, h2, h3, h4
		i := 0
		for ; i < 16; i++ {
			f := b&c | (^b)&d
			a5 := a<<5 | a>>(32-5)
			b30 := b<<30 | b>>(32-30)
			t := a5 + f + e + w[i&0xf] + _K0
			a, b, c, d, e = t, a, b30, c, d
		}
		for ; i < 20; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = tmp<<1 | tmp>>(32-1)
			f := b&c | (^b)&d
			a5 := a<<5 | a>>(32-5)
			b30 := b<<30 | b>>(32-30)
			t := a5 + f + e + w[i&0xf] + _K0
			a, b, c, d, e = t, a, b30, c, d
		}
		for ; i < 40; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = tmp<<1 | tmp>>(32-1)
			f := b ^ c ^ d
			a5 := a<<5 | a>>(32-5)
			b30 := b<<30 | b>>(32-30)
			t := a5 + f + e + w[i&0xf] + _K1
			a, b, c, d, e = t, a, b30, c, d
		}
		for ; i < 60; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = tmp<<1 | tmp>>(32-1)
			f := ((b | c) & d) | (b & c)
			a5 := a<<5 | a>>(32-5)
			b30 := b<<30 | b>>(32-30)
			t := a5 + f + e + w[i&0xf] + _K2
			a, b, c, d, e = t, a, b30, c, d
		}
		for ; i < 80; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = tmp<<1 | tmp>>(32-1)
			f := b ^ c ^ d
			a5 := a<<5 | a>>(32-5)
			b30 := b<<30 | b>>(32-30)
			t := a5 + f + e + w[i&0xf] + _K3
			a, b, c, d, e = t, a, b30, c, d
		}
		h0 += a
		h1 += b
		h2 += c
		h3 += d
		h4 += e
		p = p[chunk:]
	}
	dig.h[0], dig.h[1], dig.h[2], dig.h[3], dig.h[4] = h0, h1, h2, h3, h4
}

//End of sha1 implementation

func secretMac(key []byte, message []byte) []byte {
	s := sha1New()
	s.Write(key)
	s.Write(message)
	hash := s.checkSum()
	return hash[:]
}

func checkMac(key []byte, message []byte, mac []byte) bool {
	s := sha1New()
	s.Write(key)
	s.Write(message)
	hash := s.checkSum()
	return bytes.Equal(hash[:], mac)
}

func createMDpadding(message []byte) []byte {
	len := len(message)
	var padding []byte
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		padding = append(padding, tmp[0:56-len%64]...)
	} else {
		padding = append(padding, tmp[0:64+56-len%64]...)
	}
	len <<= 3
	putUint64(tmp[:], uint64(len))
	padding = append(padding, tmp[0:8]...)
	return padding
}

func breakHashtoUint32(hash []byte) []uint32 {
	var u []uint32
	for i := 0; i < len(hash); i = i + 4 {
		tmp := []byte{hash[i], hash[i+1], hash[i+2], hash[i+3]}
		u = append(u, binary.BigEndian.Uint32(tmp))
	}
	return u
}

func extendHash(IV []uint32, message []byte, messageToAdd []byte, key []byte) ([]byte, []byte) {
	i := 0
	for {
		d := new(digest)
		d.ResetCustom(IV)
		var forgedMessage []byte
		forgedMessage = append(forgedMessage, message...)
		padding := createMDpadding(append(forgedMessage, []byte(strings.Repeat("A", i))...))
		forgedMessage = append(forgedMessage, padding...)
		d.len = uint64(len(forgedMessage) + i)
		forgedMessage = append(forgedMessage, messageToAdd...)
		d.Write(messageToAdd)
		hash := d.checkSum()
		if checkMac(key, forgedMessage, hash[:]) == true {
			return forgedMessage, hash[:]
		}
		i++
		if i > 16 {
			panic("i too big we failed")
		}
	}
}

//Implementation of MD4 from crypto library

const md4size = 16

const md4blockSize = 64

const (
	_Chunk = 64
	_Init0 = 0x67452301
	_Init1 = 0xEFCDAB89
	_Init2 = 0x98BADCFE
	_Init3 = 0x10325476
)

type md4 struct {
	s   [4]uint32
	x   [_Chunk]byte
	nx  int
	len uint64
}

func (d *md4) Reset() {
	d.s[0] = _Init0
	d.s[1] = _Init1
	d.s[2] = _Init2
	d.s[3] = _Init3
	d.nx = 0
	d.len = 0
}

//For length extension attack
func (d *md4) ResetCustom(IV []uint32) {
	d.s[0] = IV[0]
	d.s[1] = IV[1]
	d.s[2] = IV[2]
	d.s[3] = IV[3]
	d.nx = 0
	d.len = 0
}

func newMD4() *md4 {
	d := new(md4)
	d.Reset()
	return d
}

func (d *md4) Size() int { return md4size }

func (d *md4) BlockSize() int { return md4blockSize }

func (d *md4) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := len(p)
		if n > _Chunk-d.nx {
			n = _Chunk - d.nx
		}
		for i := 0; i < n; i++ {
			d.x[d.nx+i] = p[i]
		}
		d.nx += n
		if d.nx == _Chunk {
			_Block(d, d.x[0:])
			d.nx = 0
		}
		p = p[n:]
	}
	n := _Block(d, p)
	p = p[n:]
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d0 *md4) Sum(in []byte) []byte {
	d := new(md4)
	*d = *d0

	len := d.len
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		d.Write(tmp[0 : 56-len%64])
	} else {
		d.Write(tmp[0 : 64+56-len%64])
	}
	len <<= 3
	for i := uint(0); i < 8; i++ {
		tmp[i] = byte(len >> (8 * i))
	}
	d.Write(tmp[0:8])

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	for _, s := range d.s {
		in = append(in, byte(s>>0))
		in = append(in, byte(s>>8))
		in = append(in, byte(s>>16))
		in = append(in, byte(s>>24))
	}
	return in
}

var shift1 = []uint{3, 7, 11, 19}
var shift2 = []uint{3, 5, 9, 13}
var shift3 = []uint{3, 9, 11, 15}

var xIndex2 = []uint{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
var xIndex3 = []uint{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}

func _Block(dig *md4, p []byte) int {
	a := dig.s[0]
	b := dig.s[1]
	c := dig.s[2]
	d := dig.s[3]
	n := 0
	var X [16]uint32
	for len(p) >= _Chunk {
		aa, bb, cc, dd := a, b, c, d

		j := 0
		for i := 0; i < 16; i++ {
			X[i] = uint32(p[j]) | uint32(p[j+1])<<8 | uint32(p[j+2])<<16 | uint32(p[j+3])<<24
			j += 4
		}
		for i := uint(0); i < 16; i++ {
			x := i
			s := shift1[i%4]
			f := ((c ^ d) & b) ^ d
			a += f + X[x]
			a = a<<s | a>>(32-s)
			a, b, c, d = d, a, b, c
		}

		for i := uint(0); i < 16; i++ {
			x := xIndex2[i]
			s := shift2[i%4]
			g := (b & c) | (b & d) | (c & d)
			a += g + X[x] + 0x5a827999
			a = a<<s | a>>(32-s)
			a, b, c, d = d, a, b, c
		}

		for i := uint(0); i < 16; i++ {
			x := xIndex3[i]
			s := shift3[i%4]
			h := b ^ c ^ d
			a += h + X[x] + 0x6ed9eba1
			a = a<<s | a>>(32-s)
			a, b, c, d = d, a, b, c
		}

		a += aa
		b += bb
		c += cc
		d += dd

		p = p[_Chunk:]
		n += _Chunk
	}

	dig.s[0] = a
	dig.s[1] = b
	dig.s[2] = c
	dig.s[3] = d
	return n
}

//End of md4 implementation

func secretMacMD4(key []byte, message []byte) []byte {
	s := newMD4()
	s.Write(key)
	s.Write(message)
	hash := s.Sum(nil)
	return hash[:]
}

func checkMacMD4(key []byte, message []byte, mac []byte) bool {
	s := newMD4()
	s.Write(key)
	s.Write(message)
	hash := s.Sum(nil)
	return bytes.Equal(hash[:], mac)
}

func createMD4padding(message []byte) []byte {
	len := len(message)
	var padding []byte
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		padding = append(padding, tmp[0:56-len%64]...)
	} else {
		padding = append(padding, tmp[0:64+56-len%64]...)
	}
	len <<= 3
	for i := uint(0); i < 8; i++ {
		tmp[i] = byte(len >> (8 * i))
	}
	padding = append(padding, tmp[0:8]...)
	return padding
}

func breakHashtoUint32MD4(hash []byte) []uint32 {
	var u []uint32
	for i := 0; i < len(hash); i = i + 4 {
		tmp := []byte{hash[i], hash[i+1], hash[i+2], hash[i+3]}
		u = append(u, binary.LittleEndian.Uint32(tmp))
	}
	return u
}

func extendHashMD4(IV []uint32, message []byte, messageToAdd []byte, key []byte) ([]byte, []byte) {
	i := 0
	for {
		d := new(md4)
		d.ResetCustom(IV)
		var forgedMessage []byte
		forgedMessage = append(forgedMessage, message...)
		padding := createMD4padding(append(forgedMessage, []byte(strings.Repeat("A", 10))...))
		forgedMessage = append(forgedMessage, padding...)
		d.len = uint64(len(forgedMessage) + 10)
		forgedMessage = append(forgedMessage, messageToAdd...)
		d.Write(messageToAdd)
		hash := d.Sum(nil)
		if checkMacMD4(key, forgedMessage, hash[:]) == true {
			return forgedMessage, hash[:]
		}
		i++
		if i > 16 {
			panic("i too big we failed")
		}
	}
}
