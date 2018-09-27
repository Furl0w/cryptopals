package cryptochallenges

import (
	"bufio"
	"crypto/aes"
	b64 "encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"strings"
)

//HexTo64 convert Hex string to 64 string
func HexTo64(HexString string) (string, error) {
	decodedBytes, err := hex.DecodeString(HexString)
	if err != nil {
		return "", err
	}
	return b64.StdEncoding.EncodeToString(decodedBytes), nil
}

//FixedXor does a XOR against 2 Hex String
func FixedXor(HexString1 string, HexString2 string) (string, error) {
	decodedString1, err := hex.DecodeString(HexString1)
	if err != nil {
		return "", err
	}
	decodedString2, err := hex.DecodeString(HexString2)
	if err != nil {
		return "", err
	}
	var output []byte
	for i := 0; i < len(decodedString1); i++ {
		output = append(output, decodedString1[i]^decodedString2[i])
	}
	return hex.EncodeToString(output), nil
}

//DecodeXorOneByte guess a message from a string Xored against a single byte
func DecodeXorOneByte(HexString string) (string, error) {
	decodedString, err := hex.DecodeString(HexString)
	if err != nil {
		return "", err
	}
	score := 0
	message := ""
	for b := byte(0); b < 255; b++ {
		var output []byte
		for i := 0; i < len(decodedString); i++ {
			output = append(output, decodedString[i]^b)
		}
		xoredString := string(output)
		outputScore := searchEnglishMessage(xoredString)
		if outputScore > score {
			score = outputScore
			message = xoredString
		}
	}
	return message, nil
}

func searchEnglishMessage(message string) int {
	words := []string{" be ", " is ", " are ", " have ", " has ", " the ", " of ", " and ", "tion ", "ing ", "ally ", "ics "}
	score := 0
	for i := 0; i < len(words); i++ {
		score += strings.Count(message, words[i])
	}
	return score
}

//SearchForEncryptedMessageFromFile look for an encrypted string by a single character xor in a file
func SearchForEncryptedMessageFromFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	score := 0
	finalMessage := ""
	for scanner.Scan() {
		message, _ := DecodeXorOneByte(scanner.Text())
		if message != "" {
			outputScore := searchEnglishMessage(message)
			if outputScore > score {
				score = outputScore
				finalMessage = message
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return finalMessage, nil
}

//EncryptRepeatingKeyXOR encrypt a message by repeating a XOR with a provided key
func EncryptRepeatingKeyXOR(message string, key string) []byte {
	byteMessage := []byte(message)
	byteKey := []byte(key)
	keyIndex := 0
	var output []byte
	for i := 0; i < len(byteMessage); i++ {
		output = append(output, byteMessage[i]^byteKey[keyIndex])
		keyIndex = (keyIndex + 1) % len(key)
	}
	return output
}

//HammingBetweenStrings calculate the hamming distance between 2 strings
func HammingBetweenStrings(a, b string) (int, error) {
	aHex := []byte(a)
	bHex := []byte(b)
	distance, err := hamming(aHex, bHex)
	if err != nil {
		return 0, err
	}
	return distance, nil
}

func hamming(a, b []byte) (int, error) {
	if len(a) != len(b) {
		return 0, errors.New("a b are not the same length")
	}

	diff := 0
	for i := 0; i < len(a); i++ {
		b1 := a[i]
		b2 := b[i]
		for j := 0; j < 8; j++ {
			mask := byte(1 << uint(j))
			if (b1 & mask) != (b2 & mask) {
				diff++
			}
		}
	}
	return diff, nil
}

//BreakRepeatingKeyXOR break a message encrypted by using a repeating key XOR
func BreakRepeatingKeyXOR(path string) (string, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Print(err)
	}
	content, err := b64.StdEncoding.DecodeString(string(b))
	if err != nil {
		fmt.Print(err)
	}
	keySizes, err := searchKeySize(content, 1, 40)
	if err != nil {
		return "", err
	}
	var keys [][]byte
	for i := 0; i < len(keySizes); i++ {
		fmt.Printf("size is %d\n", keySizes[i])
		keys = append(keys, breakInBlocAndGetKey(content, keySizes[i]))
	}
	for k := 0; k < len(keys); k++ {
		fmt.Printf("key is %s\n", string(keys[k][:]))
		fmt.Printf("%s\n", string(EncryptRepeatingKeyXOR(string(content), string(keys[k]))))
	}
	return "", nil
}

func searchKeySize(message []byte, numberKey int, maxKeySize int) ([]int, error) {
	var distancesSaved []float64
	for i := 2; i < maxKeySize; i++ {
		distance, err := hamming(message[0:i*15], message[i*15:i*2*15])
		if err != nil {
			return []int{}, err
		}
		distancesSaved = append(distancesSaved, float64(distance)/float64(i*10))
	}
	keys := findMinKeys(distancesSaved, numberKey)
	return keys, nil
}

func findMinKeys(a []float64, numberKeys int) (keys []int) {
	for i := 0; i < numberKeys; i++ {
		index := 0
		n := math.MaxFloat64
		for j, v := range a {
			if n > v {
				n = v
				index = j
			}
		}
		keys = append(keys, index+2)
		a[index] = a[len(a)-1]
		a[len(a)-1] = 0
		a = a[:len(a)-1]
	}
	return keys
}

func breakInBlocAndGetKey(message []byte, keySize int) []byte {
	var key []byte
	for i := 0; i < keySize; i++ {
		var block []byte
		for j := i; j < len(message); j = j + keySize {
			block = append(block, message[j])
		}
		keyPiece, err := decodeXorOneByteByScoring(block)
		if err != nil {
			panic(err)
		}
		key = append(key, keyPiece)
	}
	return key
}

func decodeXorOneByteByScoring(message []byte) (byte, error) {
	score := 999999.0
	key := byte(0)
	for b := byte(0); b < 255; b++ {
		var output []byte
		for i := 0; i < len(message); i++ {
			output = append(output, message[i]^b)
		}
		xoredString := string(output)
		outputScore := scoreEnglish(xoredString)
		if outputScore < score {
			score = outputScore
			key = b
		}
	}
	return key, nil
}

//from https://crypto.stackexchange.com/a/30259
func scoreEnglish(message string) float64 {
	englishFreq := []float64{
		0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
		0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
		0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
		0.00978, 0.02360, 0.00150, 0.01974, 0.00074}
	count := []int{}
	for i := 0; i < 26; i++ {
		count = append(count, 0)
	}
	ignored := 0
	codeMessage := []rune(message)
	for i := 0; i < len(codeMessage); i++ {
		c := codeMessage[i]
		if c >= 65 && c <= 90 {
			count[c-65]++
		} else if c >= 97 && c <= 122 {
			count[c-97]++
		} else if c >= 32 && c <= 126 {
			ignored++
		} else if c == 9 || c == 10 || c == 13 {
			ignored++
		} else {
			return 999999999999999999999999999
		}
	}
	score := 0.0
	len := len(codeMessage) - ignored
	for i := 0; i < 26; i++ {
		observed := float64(count[i])
		expected := float64(len) * englishFreq[i]
		difference := observed - expected
		score += difference * difference / expected
	}
	return score
}

func decryptAESECBMode(message []byte, key string) string {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err)
	}
	decoded := ""
	for i := 0; i < len(message)-block.BlockSize(); i += block.BlockSize() {
		decodedBlock := make([]byte, block.BlockSize(), block.BlockSize())
		block.Decrypt(decodedBlock, message[i:i+block.BlockSize()])
		decoded += string(decodedBlock)
	}

	return decoded
}
func detectECBEncrypt(corpus [][]byte) []byte {
	score := 0
	index := 0
	for i := 0; i < len(corpus); i++ {
		output := scoreECB(corpus[i])
		if output > score {
			score = output
			index = i + 1
		}
	}
	fmt.Printf("number %d\n", index)
	fmt.Printf("score is %d\n", score)
	return corpus[index]
}

func scoreECB(message []byte) int {
	lenBlock := 16
	score := 0
	var blocks [][]byte
	for i := 0; i < len(message); i += lenBlock {
		found := false
		for _, n := range blocks {
			if string(message[i:i+lenBlock]) == string(n) {
				score++
				found = true
			}
		}
		if found == false {
			blocks = append(blocks, message[i:i+lenBlock])
		}
	}
	return score
}
