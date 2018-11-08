package cryptochallenges

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"testing"
)

func TestSet5_33(t *testing.T) {
	a, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		fmt.Println(err)
	}
	A := computePublicKey(a)
	b, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		fmt.Println(err)
	}
	B := computePublicKey(b)
	keyA := deriveKey(a, B)
	keyB := deriveKey(b, A)
	if bytes.Compare(keyA, keyB) != 0 {
		fmt.Println("Keys are not equals, learn to implement")
	}
}

func TestSet5_34(t *testing.T) {
	a, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		fmt.Println(err)
	}
	b, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		fmt.Println(err)
	}
	keyA := deriveKey(a, p)
	keyB := deriveKey(b, p)
	sha256 := crypto.SHA256.New()
	keyM := sha256.Sum(big.NewInt(0).Bytes())
	sendMessageMITM(keyA, keyB, keyM, "Hello from A to B")
}

func TestSet5_35(t *testing.T) {

}
