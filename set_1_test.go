package cryptochallenges

import (
	"bufio"
	b64 "encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

func TestSet1_1(t *testing.T) {
	res, err := HexTo64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	if err != nil {
		log.Fatal(err)
	}
	if res != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
		log.Fatal("wrong string")
	}
}

func TestSet1_2(t *testing.T) {
	res, err := FixedXor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")
	if err != nil {
		log.Fatal(err)
	}
	if res != "746865206b696420646f6e277420706c6179" {
		log.Fatal("wrong string")
	}
}

func TestSet1_3(t *testing.T) {
	res, err := DecodeXorOneByte("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", res)
}

func TestSet1_4(t *testing.T) {
	res, err := SearchForEncryptedMessageFromFile("./4.txt")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s", res)
}

func TestSet1_5(t *testing.T) {
	res := hex.EncodeToString(EncryptRepeatingKeyXOR("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE"))
	if res != `0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f` {
		log.Fatal("wrong string")
	}
}

func TestSet1_6_Hamming(t *testing.T) {
	res, err := HammingBetweenStrings("this is a test", "wokka wokka!!!")
	if err != nil {
		log.Fatal(err)
	}
	if res != 37 {
		log.Fatal("wrong distance")
	}
}

func TestSet1_6(t *testing.T) {
	_, err := BreakRepeatingKeyXOR("6.txt")
	if err != nil {
		log.Fatal(err)
	}
}

func TestSet1_7(t *testing.T) {
	raw, err := ioutil.ReadFile("7.txt")
	if err != nil {
		panic(err)
	}
	message := make([]byte, len(raw), len(raw))
	b64.StdEncoding.Decode(message, raw)
	resp := decryptAESECBMode(message, "YELLOW SUBMARINE")
	fmt.Printf("%s\n", resp)
}

func TestSet1_8(t *testing.T) {
	var corpus [][]byte
	file, err := os.Open("8.txt")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		decodedMessage, err := hex.DecodeString(scanner.Text())
		if err != nil {
			panic(err)
		}
		corpus = append(corpus, decodedMessage)
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}
	detectECBEncrypt(corpus)
}
