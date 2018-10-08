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

func TestSet2_9(t *testing.T) {
	res := paddingPKCS7("YELLOW SUBMARINE", 20)
	fmt.Printf("%q\n", res)
}

func TestSet2_10_encryption(t *testing.T) {
	block, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	if err != nil {
		panic(err)
	}
	encrypted := encryptECB([]byte("YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE"), block)
	decrypted := decryptECB(encrypted, block)
	if decrypted != "YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE" {
		fmt.Printf("wrong decryption %q\n", decrypted)
	}
}

func TestSet2_10_CBC(t *testing.T) {
	block, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	message, err := ioutil.ReadFile("10.txt")
	if err != nil {
		panic(err)
	}
	decodedMessage, err := b64.StdEncoding.DecodeString(string(message))
	if err != nil {

	}
	decrypted := decryptCBC(decodedMessage, block, make([]byte, block.BlockSize()))
	fmt.Printf("%s\n", stripNonPrintable(string(decrypted)))
}

func TestSet2_11(t *testing.T) {
	for i := 0; i < 10; i++ {
		message := generateRandom(2650)
		encrypted := encryptRandom(message)
		score := scoreECB(encrypted)
		if score > 0 {
			fmt.Println("ECB encryption detected")
		}
	}
}

func TestSet2_12(t *testing.T) {
	message, err := ioutil.ReadFile("12.txt")
	if err != nil {
		panic(err)
	}
	unknown, err := b64.StdEncoding.DecodeString(string(message))
	if err != nil {
		panic(err)
	}
	encrypted := appendAndEncrypt([]byte(strings.Repeat("A", 48)), unknown)
	var blockSize int
	if scoreECB(encrypted) > 0 {
		fmt.Println("ECB detected")
	}
	if bytes.Compare(encrypted[:15], encrypted[16:31]) == 0 {
		fmt.Println("Block size is 16")
		blockSize = 16
	} else if bytes.Compare(encrypted[:23], encrypted[24:47]) == 0 {
		fmt.Println("Block size is 24")
		blockSize = 24
	} else {
		fmt.Println("Block size is 32")
		blockSize = 32
	}
	decrypted := breakECB(unknown, blockSize)
	fmt.Printf("%s\n", stripNonPrintable(string(decrypted)))
	fmt.Printf("%s\n", unknown)
}

func TestSet2_13_userFunctions(t *testing.T) {
	fmt.Println("testing parsing and encoding")
	user := profileFor("foo@bar.com")
	encoded := encodeUser(user)
	parsed := parseUser(encoded)
	if strings.Compare(encodeUser(user), encodeUser(parsed)) != 0 {
		fmt.Println("Oops looks like something is broken")
	}
	fmt.Println("testing resistance to injection")
	userAdmin := profileFor("foo@bar.com&role=admin")
	if parseUser(encodeUser(userAdmin)).role == "admin" {
		fmt.Println("Parsing is hard right ?")
	}
	fmt.Println("testing for multiple key value")
	if parseUser(encodeUser(userAdmin)+"&role=admin").role == "admin" {
		fmt.Println("Last key is taken instead of first")
	}
	fmt.Println("testing encryption and decryption")
	key := generateRandom(16)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	encrypted := encryptUser(encoded, block)
	decryptedUser := decryptUser(encrypted, block)
	if user.email != decryptedUser.email || user.uid != decryptedUser.uid || user.role != decryptedUser.role {
		fmt.Println("encryption/decryption broken")
		fmt.Println(encodeUser(user))
		fmt.Printf("%q\n", encodeUser(decryptedUser))
	}
}

func TestSet2_13(t *testing.T) {
	key := generateRandom(16)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	adminUser := makeAdminUser(block)
	if adminUser.role != "admin" {
		fmt.Println("Failed to create Admin user")
	}
	fmt.Printf("%q\n", encodeUser(adminUser))
}
func TestSet2_14(t *testing.T) {
	message, err := ioutil.ReadFile("12.txt")
	if err != nil {
		panic(err)
	}
	unknown, err := b64.StdEncoding.DecodeString(string(message))
	if err != nil {
		panic(err)
	}
	//For the speed I'll skip the part where we guess blocksize but we could have
	//used the same way as number 12
	blockSize := 16
	marker := findMarkerBlock(unknown, blockSize)
	decrypted := breakECBRandomPrefix(unknown, blockSize, marker)
	fmt.Printf("%s\n", stripNonPrintable(string(decrypted)))
	fmt.Printf("%s\n", unknown)
}

func TestSet2_15(t *testing.T) {
	unpadded, err := stripPaddingPKCS7("ICE ICE BABY\x04\x04\x04\x04")
	if err != nil {
		fmt.Printf("Wrong padding for : %s\n", "ICE ICE BABY\x04\x04\x04\x04")
	} else {
		fmt.Printf("Good padding : %s\n", unpadded)
	}
	unpadded2, err := stripPaddingPKCS7("ICE ICE BABY\x05\x05\x05\x05")
	if err != nil {
		fmt.Printf("Wrong padding : %q\n", "ICE ICE BABY\x05\x05\x05\x05")
	} else {
		fmt.Printf("Good padding : %s\n", unpadded2)
	}
	unpadded3, err := stripPaddingPKCS7("ICE ICE BABY\x01\x02\x03\x04")
	if err != nil {
		fmt.Printf("Wrong padding : %q\n", "ICE ICE BABY\x01\x02\x03\x04")
	} else {
		fmt.Printf("Good padding : %s\n", unpadded3)
	}
}
