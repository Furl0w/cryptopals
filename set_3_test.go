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
