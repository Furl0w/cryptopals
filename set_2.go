package cryptochallenges

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	mrand "math/rand"
	"net/url"
	"strings"
	"time"
	"unicode"
)

var key = []byte("vghbjyubiibiu153")

func paddingPKCS7(message string, size int) string {
	paddedMessage := message
	paddingSize := 0
	if len(message)%size != 0 {
		paddingSize = size - (len(message) % size)
		for i := 0; i < paddingSize; i++ {
			paddedMessage += string(byte(paddingSize))
		}
	}
	return paddedMessage
}

func decryptECB(message []byte, block cipher.Block) string {
	decoded := ""
	for i := 0; i < len(message); i += block.BlockSize() {
		decodedBlock := make([]byte, block.BlockSize())
		block.Decrypt(decodedBlock, message[i:i+block.BlockSize()])
		decoded += string(decodedBlock)
	}
	return decoded
}
func encryptECB(message []byte, block cipher.Block) []byte {
	var encrypted []byte
	message = []byte(paddingPKCS7(string(message), block.BlockSize()))
	for i := 0; i < len(message); i += block.BlockSize() {
		decodedBlock := make([]byte, block.BlockSize())
		block.Encrypt(decodedBlock, message[i:i+block.BlockSize()])
		encrypted = append(encrypted, decodedBlock...)
	}
	return encrypted
}

func decryptCBC(message []byte, block cipher.Block, IV []byte) []byte {
	var decrypted []byte
	for i := 0; i < len(message); i += block.BlockSize() {
		prev := i - block.BlockSize()
		decodedBlock := make([]byte, block.BlockSize())
		block.Decrypt(decodedBlock, message[i:i+block.BlockSize()])
		if i == 0 {
			for j := range decodedBlock {
				decrypted = append(decrypted, decodedBlock[j]^IV[j])
			}
		} else {
			for j := range decodedBlock {
				decrypted = append(decrypted, decodedBlock[j]^message[prev+j])
			}
		}
	}
	return decrypted
}

func encryptCBC(message []byte, block cipher.Block, IV []byte) []byte {
	var encrypted []byte
	message = []byte(paddingPKCS7(string(message), block.BlockSize()))
	for i := 0; i < len(message); i += block.BlockSize() {
		var xoredBlock []byte
		if i == 0 {
			for k := 0; k < block.BlockSize(); k++ {
				xoredBlock = append(xoredBlock, message[k]^IV[k])
			}
		} else {
			for k := 0; k < block.BlockSize(); k++ {
				xoredBlock = append(xoredBlock, message[i+k]^encrypted[i-block.BlockSize()+k])
			}
		}
		b := make([]byte, block.BlockSize())
		block.Encrypt(b, xoredBlock)
		encrypted = append(encrypted, b...)
	}
	return encrypted
}

func generateRandom(length int) []byte {
	random := make([]byte, length)
	_, err := rand.Read(random)
	if err != nil {
		panic(err)
	}
	return random
}

func encryptRandom(message []byte) []byte {
	key := generateRandom(16)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	modifiedMessage := appendChosenBytes(message, 10)
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	mode := r.Intn(2)
	encrypted := make([]byte, len(message))
	fmt.Printf("mode is %d\n", mode)
	if mode == 0 {
		encrypted = encryptECB(modifiedMessage, block)
	} else {
		encrypted = encryptCBC(modifiedMessage, block, generateRandom(block.BlockSize()))
	}
	return encrypted
}

func appendChosenBytes(message []byte, l int) []byte {
	newMessage := make([]byte, len(message)+2*l)
	chosenBytes := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	for i := 0; i < l; i++ {
		newMessage = append(newMessage, chosenBytes[i])
	}
	for i := 0; i < len(message); i++ {
		newMessage = append(newMessage, message[i])
	}
	for i := 0; i < l; i++ {
		newMessage = append(newMessage, chosenBytes[i])
	}
	return newMessage
}

func appendAndEncrypt(input []byte, unknown []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	input = append(input, unknown...)
	encrypted := encryptECB(input, block)
	return encrypted
}

func breakECB(unknown []byte, sizeBlock int) []byte {
	var decrypted []byte
	for j := 0; j < len(unknown)/sizeBlock+1; j++ {
		for i := 0; i < sizeBlock; i++ {
			input := strings.Repeat("A", sizeBlock-1-i)
			encryptedBlock := appendAndEncrypt([]byte(input), unknown)[j*sizeBlock : (j+1)*sizeBlock]
			for b := byte(0); b < 255; b++ {
				searchBlock := appendAndEncrypt(append(append([]byte(input), decrypted...), b), unknown)[j*sizeBlock : (j+1)*sizeBlock]
				if bytes.Compare(searchBlock, encryptedBlock) == 0 {
					decrypted = append(decrypted, b)
					break
				}
			}
		}
	}
	return decrypted
}

type user struct {
	email string
	uid   string
	role  string
}

func encodeUser(user user) string {
	return "email=" + user.email + "&uid=" + user.uid + "&role=" + user.role
}

func parseUser(encoded string) user {
	var user user
	reader, err := url.ParseQuery(encoded)
	if err != nil {
		panic(err)
	}
	user.email = reader.Get("email")
	user.uid = reader.Get("uid")
	user.role = reader.Get("role")
	return user
}

func profileFor(email string) user {
	var user user
	if strings.Index(email, "&") != -1 {
		email = email[:strings.Index(email, "&")]
	}
	user.email = email
	user.uid = base64.StdEncoding.EncodeToString(generateRandom(2))
	user.role = "user"
	return user
}

func encryptUser(encoded string, block cipher.Block) []byte {
	return encryptECB([]byte(encoded), block)
}

func decryptUser(encrypted []byte, block cipher.Block) user {
	encoded := string(decryptECB(encrypted, block))
	encoded = stripNonPrintable(encoded)
	return parseUser(encoded)
}

//email=AAAAAAAAA@ A.A&uid=aa&role= admin&uid=aa&role=user + padding
//AAAAAAA@A.foobar [:15]
//AAAAAAA@A.A[16:31]
//AAAAAAA@a.admin [16:]
func makeAdminUser(block cipher.Block) user {
	block1 := encryptUser(encodeUser(profileFor("AAAAAAA@A.foobar")), block)[:16]
	block2 := encryptUser(encodeUser(profileFor("AAAAAAA@A.A")), block)[16:32]
	block3 := encryptUser(encodeUser(profileFor("AAAAAAA@a.admin")), block)[16:]
	return decryptUser([]byte(string(block1)+string(block2)+string(block3)), block)
}

func appendAndEncryptRandomPrefix(input []byte, unknown []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	input = append(append(generateRandom(r.Intn(block.BlockSize()+1)), []byte(input)...), unknown...)
	encrypted := encryptECB(input, block)
	return encrypted
}

func breakECBRandomPrefix(unknown []byte, sizeBlock int, markerBlock []byte) []byte {
	var decrypted []byte
	for j := 0; j < len(unknown)/sizeBlock+1; j++ {
		for i := 0; i < sizeBlock; i++ {
			input := strings.Repeat("A", sizeBlock) + strings.Repeat("B", sizeBlock-1-i)
			var encryptedBlock []byte
			var testBlock []byte
			for ok := true; ok; ok = bytes.Compare(testBlock[sizeBlock:sizeBlock*2], markerBlock) != 0 {
				testBlock = appendAndEncryptRandomPrefix([]byte(input), unknown)
			}
			encryptedBlock = testBlock[(j+2)*sizeBlock : (j+3)*sizeBlock]
			for b := byte(0); b < 255; b++ {
				var searchBlock []byte
				for ok := true; ok; ok = bytes.Compare(searchBlock[sizeBlock:sizeBlock*2], markerBlock) != 0 {
					searchBlock = appendAndEncryptRandomPrefix(append(append([]byte(input), decrypted...), b), unknown)
				}
				searchBlock = searchBlock[(j+2)*sizeBlock : (j+3)*sizeBlock]
				if bytes.Compare(searchBlock, encryptedBlock) == 0 {
					decrypted = append(decrypted, b)
					break
				}
			}
		}
	}
	return decrypted
}

func findMarkerBlock(unknown []byte, sizeBlock int) []byte {
	encrypted := appendAndEncryptRandomPrefix([]byte(strings.Repeat("A", sizeBlock*3)), unknown)
	var blocks [][]byte
	for i := 0; i < len(encrypted); i += sizeBlock {
		for _, n := range blocks {
			if bytes.Compare(encrypted[i:i+sizeBlock], n) == 0 {
				return encrypted[i : i+sizeBlock]
			}
		}
		blocks = append(blocks, encrypted[i:i+sizeBlock])

	}
	return []byte{}
}

func stripNonPrintable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) || r == rune('\n') {
			return r
		}
		return -1
	}, s)
}

func stripPaddingPKCS7(s string) (string, error) {
	p := false
	i := len(s) - 1
	padding := ""
	for p == false {
		if unicode.IsPrint(rune(s[i])) || rune(s[i]) == rune('\n') {
			p = true
		} else {
			padding += string(s[i])
		}
		i--
	}
	paddingValid := true
	if len(padding) > 0 {
		for i := 0; i < len(padding); i++ {
			if padding[i] != byte(len(padding)) {
				paddingValid = false
				break
			}
		}
	}
	err := errors.New("Wrong encryption")
	if paddingValid == true {
		s = s[:len(s)-len(padding)]
		err = nil
	}
	return s, err
}

func concatAndEncrypt(prefix string, userdata string, suffix string, block cipher.Block, IV []byte) []byte {
	userdata = strings.Map(func(r rune) rune {
		if r == rune('=') || r == rune(';') {
			return -1
		}
		return r
	}, userdata)
	query := paddingPKCS7(prefix+userdata+suffix, block.BlockSize())
	return encryptCBC([]byte(query), block, IV)
}

//comment1=cooking %20MCs;userdata= AAAAAAAAAAAAAAAAA AAAAAAadminAtrue ;comment2=%20like%20a%20pound%20of%20bacon
//Flip 5 and 11 from third block, A to ; and A to =
func makeAdmin(prefix string, suffix string, block cipher.Block, IV []byte) string {
	encrypted := concatAndEncrypt(prefix, "AAAAAAAAAAAAAAAAAAAAAAadminAtrue", suffix, block, IV)
	encrypted[block.BlockSize()*2+5] = encrypted[block.BlockSize()*2+5] ^ byte('A') ^ byte(';')
	encrypted[block.BlockSize()*2+11] = encrypted[block.BlockSize()*2+11] ^ byte('A') ^ byte('=')
	decrypted, err := stripPaddingPKCS7(string(decryptCBC(encrypted, block, IV)))
	if err != nil {
		panic(err)
	}
	return decrypted
}
