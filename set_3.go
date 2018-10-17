package cryptochallenges

import (
	"crypto/cipher"
	"encoding/binary"
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
