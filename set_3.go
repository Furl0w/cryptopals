package cryptochallenges

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"math"
	"strconv"
	"time"
)

func createCipher(message []byte, block cipher.Block) ([]byte, []byte) {
	IV := generateRandom(16)
	return encryptCBC(message, block, IV), IV
}

func checkPadding(encrypted []byte, block cipher.Block, IV []byte) bool {
	decrypted := decryptCBC(encrypted, block, IV)
	_, err := stripPaddingPKCS7(string(decrypted))
	if err != nil {
		return false
	}
	return true
}

func breakCBCPaddingOracle(cipher []byte, IV []byte, block cipher.Block) []byte {
	decrypted := make([]byte, len(cipher))
	var blocks [][]byte
	for i := 0; i < len(cipher)/block.BlockSize(); i++ {
		end := i*block.BlockSize() + block.BlockSize()
		if end > len(cipher) {
			end = len(cipher)
		}
		blocks = append(blocks, cipher[i*block.BlockSize():end])
	}
	for i := 1; i < len(blocks); i++ {
		decryptedBlock := breakBlockPaddingOracle(blocks[len(blocks)-1-i], blocks[len(blocks)-i], IV, block)
		copy(decrypted[len(cipher)-len(decryptedBlock)*i:], decryptedBlock)
	}
	copy(decrypted, breakBlockPaddingOracle(IV, blocks[0], IV, block))
	return decrypted
}

func breakBlockPaddingOracle(prevBlock []byte, targetBlock []byte, IV []byte, block cipher.Block) []byte {
	decryptedBlock := make([]byte, len(targetBlock))
	done := false
	last := 0
	lastSuccessfullBit := make([]byte, len(targetBlock))
	for done == false {
		for i := last; i < len(targetBlock); i++ {
			inputBlock := make([]byte, len(prevBlock))
			copy(inputBlock, prevBlock)
			for j := 0; j < i; j++ {
				inputBlock[len(inputBlock)-1-j] ^= decryptedBlock[len(inputBlock)-1-j] ^ byte(i+1)
			}
			found := false
			for b := lastSuccessfullBit[i]; b < 255; b++ {
				inputBlock[len(inputBlock)-i-1] = prevBlock[len(inputBlock)-i-1] ^ b ^ byte(i+1)
				cipher := make([]byte, len(targetBlock)*2)
				copy(cipher, inputBlock)
				copy(cipher[len(inputBlock):], targetBlock)
				lastSuccessfullBit[i] = b + 1
				if checkPadding(cipher, block, IV) != false {
					decryptedBlock[len(targetBlock)-i-1] = b
					found = true
					break
				}
			}
			if found == false {
				if i == 0 || lastSuccessfullBit[0] == byte(255) {
					panic("impossible")
				} else {
					lastSuccessfullBit[i] = 0
					last = i - 1
				}
				break
			}
			if i == len(targetBlock)-1 {
				done = true
			}
		}
	}
	return decryptedBlock
}

func encryptCTR(message []byte, nonce []byte, block cipher.Block) []byte {
	encrypted := make([]byte, len(message))
	counter := make([]byte, 8)
	keystream := make([]byte, block.BlockSize())
	for i := 0; i < len(message); i++ {
		if i%16 == 0 {
			binary.LittleEndian.PutUint64(counter, uint64(i/16))
			block.Encrypt(keystream, append(nonce, counter...))
		}
		encrypted[i] = message[i] ^ keystream[i%16]
	}
	return encrypted
}

func breakCTRRepeatingKey(texts []byte, lenKeystream int) []byte {
	var keystream []byte
	keystream = breakInBlocAndGetKey(texts, lenKeystream)
	return keystream
}

//Initial values for MT19937-64
var w, n, m, r, f = uint64(64), uint64(312), uint64(156), uint64(31), uint64(6364136223846793005)
var a, _ = strconv.ParseUint("B5026F5AA96619E9", 16, 64)
var d, _ = strconv.ParseUint("5555555555555555", 16, 64)
var b, _ = strconv.ParseUint("71D67FFFEDA60000", 16, 64)
var c, _ = strconv.ParseUint("FFF7EEE000000000", 16, 64)
var u, s, t, l = uint64(29), uint64(17), uint64(37), uint64(43)
var lowerMask = uint64((1 << r) - 1)
var upperMask = ^lowerMask

func seedMersenneTwister19937(mT []uint64, index *uint64, seed uint64) {
	*index = n
	mT[0] = seed
	for i := uint64(1); i < (n - 1); i++ {
		mT[i] = f*(mT[i-1]^(mT[i-1]>>(w-2))) + i
	}
}

func extractNumberMersenneTwister19937(mT []uint64, index *uint64) uint64 {
	if *index >= n {
		if *index > n {
			panic("MT19937 not seeded")
		}
		twistMersenneTwister19937(mT, index)
	}

	y := mT[*index]
	y ^= ((y >> u) & d)
	y ^= ((y << s) & b)
	y ^= ((y << t) & c)
	y ^= (y >> l)

	*index = *index + 1
	return y
}

func twistMersenneTwister19937(mT []uint64, index *uint64) {
	for i := uint64(0); i < (n - 1); i++ {
		x := mT[i]&upperMask + (mT[(i+1)%n] & lowerMask)
		xA := x >> 1
		if (x % 2) != 0 {
			xA = xA ^ a
		}
		mT[i] = mT[(i+m)%n] ^ xA
	}
	*index = 0
}

func breakSeedMersenneTwister19937(mT []uint64, index *uint64, now int64, output uint64) uint64 {
	seed := uint64(now)
	for {
		seed--
		seedMersenneTwister19937(mT, index, seed)
		testOutput := extractNumberMersenneTwister19937(mT, index)
		if output == testOutput {
			return seed
		}
	}
}

func invertState(extracted uint64) uint64 {
	extracted ^= (extracted >> l)
	extracted ^= ((extracted << t) & c)
	for i := 0; i < 3; i++ {
		extracted ^= ((extracted << s) & b)
	}
	extracted ^= ((extracted >> u) & d)
	return extracted
}

func encryptMT19937(message []byte, seed uint16) []byte {
	encrypted := make([]byte, len(message))
	mT := make([]uint64, n)
	index := n + 1
	seedMersenneTwister19937(mT, &index, uint64(seed))
	var keystream byte
	for i := 0; i < len(message); i++ {
		keystream = uint8(extractNumberMersenneTwister19937(mT, &index) ^ uint64(1<<56))
		encrypted[i] = message[i] ^ keystream
	}
	return encrypted
}

func breakSeedFromCipher(cipher []byte, supplied []byte) (uint16, error) {
	startIndex := len(cipher) - len(supplied)
	attackerSuppliedCipher := cipher[startIndex:]
	keystream := make([]uint8, len(supplied))
	for i, n := range attackerSuppliedCipher {
		keystream[i] = n ^ supplied[i]
	}
	for i := uint16(0); i < math.MaxUint16; i++ {
		mT := make([]uint64, n)
		index := n + 1
		seedMersenneTwister19937(mT, &index, uint64(i))
		testKeyStream := make([]uint8, len(supplied))
		for j := 0; j < len(cipher); j++ {
			if j >= startIndex {
				testKeyStream[j-startIndex] = uint8(extractNumberMersenneTwister19937(mT, &index) ^ uint64(1<<56))
			} else {
				extractNumberMersenneTwister19937(mT, &index)
			}
		}
		if bytes.Equal(keystream, testKeyStream) == true {
			return i, nil
		}
	}
	return 0, errors.New("Didn't find seed")
}

func createToken(key uint64) []byte {
	lenToken := 16
	token := make([]byte, lenToken)
	mT := make([]uint64, n)
	index := n + 1
	seedMersenneTwister19937(mT, &index, key)
	for i := 0; i < lenToken; i++ {
		token[i] = uint8(extractNumberMersenneTwister19937(mT, &index) ^ uint64(1<<56))
	}
	return token
}

func detectTimeSeedingToken(token []byte) bool {
	//Checking only for the last hour obviously we could check for more
	startingTime := uint64(time.Now().Unix())
	for i := uint64(0); i < 60*60; i++ {
		mT := make([]uint64, n)
		index := n + 1
		seedMersenneTwister19937(mT, &index, startingTime-i)
		testToken := make([]byte, len(token))
		for i := 0; i < len(token); i++ {
			testToken[i] = uint8(extractNumberMersenneTwister19937(mT, &index) ^ uint64(1<<56))
		}
		if bytes.Equal(token, testToken) == true {
			return true
		}
	}
	return false
}
