package cryptochallenges

import (
	"crypto/cipher"
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
