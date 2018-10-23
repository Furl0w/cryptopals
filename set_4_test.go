package cryptochallenges

import (
	"crypto/aes"
	b64 "encoding/base64"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"
)

func TestSet4_25(t *testing.T) {
	//testing editing ciphertext
	block, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, 8)
	message := "This a test"
	edited := seekAndAppendNewtext(encryptCTR([]byte(message), nonce, block), nonce, block, 6, []byte("n edit"))
	fmt.Printf("%q\n\n", encryptCTR(edited, nonce, block))

	//Breaking editing
	plaintext, err := ioutil.ReadFile("25.txt")
	if err != nil {
		panic(err)
	}
	unknownMessage := make([]byte, len(plaintext))
	b64.StdEncoding.Decode(unknownMessage, plaintext)
	plainUnknownMessage := decryptAESECBMode(unknownMessage, "YELLOW SUBMARINE")
	cipher := encryptCTR([]byte(plainUnknownMessage), nonce, block)
	recoveredMessage := attackSeekCTR(cipher, nonce, block)
	fmt.Printf("%s\n", recoveredMessage)
}

func TestSet4_26(t *testing.T) {
	prefix := "comment1=cooking%20MCs;userdata="
	suffix := ";comment2=%20like%20a%20pound%20of%20bacon"
	key := generateRandom(16)
	nonce := generateRandom(8)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	encrypted := concatAndEncryptCTR(prefix, "AAA;admin=true", suffix, nonce, block)
	decrypted := string(encryptCTR(encrypted, nonce, block))
	if strings.Index(decrypted, ";admin=true;") != -1 {
		fmt.Println("Learn to parse")
	}
	admin := makeAdminCTR(prefix, suffix, nonce, block)
	if strings.Index(admin, ";admin=true;") != -1 {
		fmt.Println("Admin acquired")
	} else {
		fmt.Println("Not an admin")
	}
	fmt.Printf("%q\n", admin)
}

func TestSet4_27(t *testing.T) {

}
