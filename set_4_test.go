package cryptochallenges

import (
	"bytes"
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
	plaintext, err := ioutil.ReadFile("./src/25.txt")
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

	prefix := "comment1=cooking%20MCs;userdata="
	suffix := ";comment2=%20like%20a%20pound%20of%20bacon"
	key := generateRandom(16)
	iv := key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	encrypted := concatAndEncrypt(prefix, "AAAAAAAAAAAAAAAA", suffix, block, iv)
	copy(encrypted[block.BlockSize():], make([]byte, 16))
	copy(encrypted[block.BlockSize()*2:], encrypted[:16])
	decrypted := decryptCBC(encrypted, block, iv)
	for _, n := range decrypted {
		if rune(n) > 126 {
			fmt.Println("High ascii found in decrypted")
			break
		}
	}
	recoveredKey := make([]byte, 16)
	for i := 0; i < block.BlockSize(); i++ {
		recoveredKey[i] = decrypted[i] ^ decrypted[i+2*block.BlockSize()]
	}
	if bytes.Compare(key, recoveredKey) != 0 {
		fmt.Println("Wrong recovering key")
	} else {
		fmt.Println("key recovered")
	}
	fmt.Printf("key was %q\n", key)
	fmt.Printf("recovered is %q\n", recoveredKey)
}

func TestSet4_28(t *testing.T) {
	key := "YELLOW SUBMARINE"
	message := "This is my message to authenticate"
	sha1 := secretMac([]byte(key), []byte(message))
	if checkMac([]byte(key), []byte(message), sha1) == false {
		fmt.Println("Learn to implement")
	}
	fmt.Printf("%s\n", b64.StdEncoding.EncodeToString(sha1))
}

func TestSet4_29(t *testing.T) {
	key := "Angstrom's"
	message := "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
	sha1 := secretMac([]byte(key), []byte(message))
	IV := breakHashtoUint32(sha1)
	messageToAdd := ";admin=true"
	forgedMessage, hash := extendHash(IV, []byte(message), []byte(messageToAdd), []byte(key))
	fmt.Printf("forged %s\n", b64.StdEncoding.EncodeToString(hash))
	if strings.Index(string(forgedMessage), ";admin=true") != -1 {
		fmt.Println("Admin acquired")
	} else {
		fmt.Println("Not an admin")
	}
}

func TestSet4_30(t *testing.T) {
	key := "Angstrom's"
	message := "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
	md4 := secretMacMD4([]byte(key), []byte(message))
	IV := breakHashtoUint32MD4(md4)
	messageToAdd := ";admin=true"
	forgedMessage, hash := extendHashMD4(IV, []byte(message), []byte(messageToAdd), []byte(key))
	fmt.Printf("forged %s\n", b64.StdEncoding.EncodeToString(hash))
	if strings.Index(string(forgedMessage), ";admin=true") != -1 {
		fmt.Println("Admin acquired")
	} else {
		fmt.Println("Not an admin")
	}
}

func TestSet4_31(t *testing.T) {

}
