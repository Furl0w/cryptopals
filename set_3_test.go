package cryptochallenges

import (
	"bufio"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"os"
	"testing"
)

func TestSet3_17(t *testing.T) {
	block, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	if err != nil {
		panic(err)
	}
	file, err := os.Open("17.txt")
	if err != nil {
		fmt.Printf("ERROR : couldn't open file at specified path\n")
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		decoded, err := base64.StdEncoding.DecodeString(scanner.Text())
		if err != nil {
			panic(err)
		}
		cipher, IV := createCipher(decoded, block)
		decrypted := breakCBCPaddingOracle(cipher, IV, block)
		unpadded, err := stripPaddingPKCS7(string(decrypted))
		if err != nil {
			fmt.Printf("%q\n", decrypted)
		} else {
			fmt.Printf("%q\n", unpadded)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("\nERROR : couldn't read the file at specified path")
	}
}

func TestSet3_18(t *testing.T) {
	message, err := base64.StdEncoding.DecodeString("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, 8)
	block, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	if err != nil {
		panic(err)
	}
	fmt.Printf("%q\n", encryptCTR(message, nonce, block))
}

//TO DO number 19
//I First tried to solve it statistically but it ended up being the same as 20
//Might go back to it if I have time but since it teaches nothing I'm less interested
func TestSet3_19(t *testing.T) {
	block, err := aes.NewCipher(generateRandom(16))
	nonce := make([]byte, 8)
	var encryptedTexts [][]byte
	if err != nil {
		panic(err)
	}
	file, err := os.Open("19.txt")
	if err != nil {
		fmt.Printf("ERROR : couldn't open file at specified path\n")
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		decoded, err := base64.StdEncoding.DecodeString(scanner.Text())
		if err != nil {
			panic(err)
		}
		encryptedTexts = append(encryptedTexts, encryptCTR(decoded, nonce, block))
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("ERROR : couldn't read the file at specified path\n")
	}
	for _, n := range encryptedTexts {
		fmt.Printf("%q\n", n)
	}
}

func TestSet3_20(t *testing.T) {
	block, err := aes.NewCipher(generateRandom(16))
	nonce := make([]byte, 8)
	var encryptedTexts [][]byte
	if err != nil {
		panic(err)
	}
	file, err := os.Open("20.txt")
	if err != nil {
		fmt.Printf("ERROR : couldn't open file at specified path\n")
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		decoded, err := base64.StdEncoding.DecodeString(scanner.Text())
		if err != nil {
			panic(err)
		}
		encryptedTexts = append(encryptedTexts, encryptCTR(decoded, nonce, block))
	}
	lenKeystream := 999999
	for _, n := range encryptedTexts {
		if len(n) < lenKeystream {
			lenKeystream = len(n)
		}
	}
	var texts []byte
	for _, n := range encryptedTexts {
		var text []byte
		if lenKeystream < len(n) {
			text = n[:lenKeystream]
		}
		texts = append(texts, text...)
	}
	keystream := breakCTRRepeatingKey(texts, lenKeystream)
	//Correcting bad detection
	//Again could do better with my scoring function
	//Because the cipher is random depending on the key sometimes a few character will break
	//Should still be pretty readable
	keystream[0] ^= byte('+') ^ byte('I')
	keystream[1] ^= byte('n') ^ byte('\'')
	keystream[2] ^= byte('3') ^ byte('m')
	keystream[8] ^= byte('$') ^ byte('d')
	keystream[12] ^= byte('?') ^ byte('a')
	keystream[13] ^= byte('#') ^ byte('c')
	keystream[15] ^= byte('|') ^ byte(' ')
	keystream[24] ^= byte('0') ^ byte('k')
	keystream[27] ^= byte('%') ^ byte('e')
	keystream[27] ^= byte('!') ^ byte('a')
	keystream[31] ^= byte('3') ^ byte('s')
	keystream[37] ^= byte('4') ^ byte('t')

	for _, n := range encryptedTexts {
		decrypted := make([]byte, lenKeystream)
		for i := 0; i < lenKeystream; i++ {
			decrypted[i] = n[i] ^ keystream[i]
		}
		fmt.Printf("%q\n", decrypted)
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("ERROR : couldn't read the file at specified path\n")
	}
}
