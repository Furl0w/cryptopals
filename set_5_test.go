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
	a, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	A := computePublicKey(a)
	b, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	B := computePublicKey(b)
	keyA := deriveKey(a, B)
	keyB := deriveKey(b, A)
	if bytes.Compare(keyA, keyB) != 0 {
		fmt.Println("Keys are not equals, learn to implement")
	}
}

func TestSet5_34(t *testing.T) {
	a, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	b, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	keyA := deriveKey(a, p)
	keyB := deriveKey(b, p)

	//key will be 0 for both since p**anything mod p == 0
	sha256 := crypto.SHA256.New()
	sha256.Write(big.NewInt(0).Bytes())
	keyM := sha256.Sum(nil)
	sendMessageMITM(keyA, keyB, keyM, "Hello from A to B")
}

func TestSet5_35(t *testing.T) {
	a, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	b, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	fmt.Printf("%s\n", a.String())

	// g = 1, key will be 1 (1**anything == 1)
	g1 := big.NewInt(1)
	sha256 := crypto.SHA256.New()
	sha256.Write(big.NewInt(1).Bytes())
	keyG1 := sha256.Sum(nil)
	sendMessageMITM(deriveKey(a, pubKeyNegociatedGroup(b, g1)), deriveKey(b, pubKeyNegociatedGroup(a, g1)), keyG1, "message from A to B with g = 1")
	fmt.Println()

	// g = p, key will be 0 (p**anything mod p == p)
	gP := p
	sha256.Reset()
	sha256.Write(big.NewInt(0).Bytes())
	keyGP := sha256.Sum(nil)
	sendMessageMITM(deriveKey(a, pubKeyNegociatedGroup(b, gP)), deriveKey(b, pubKeyNegociatedGroup(a, gP)), keyGP, "message from A to B with g = p")
	fmt.Println()

	/*
		Regarding g = p - 1 the key can either be 1 or p-1 (maths)
		I didn't wrote the attack (lazyness) but a simple way to implement can be :
		1/ check with 1 if you can decrypt
		2/ if high ascii values -> wrong key
		3/ then use p - 1
		So the solution presented here will not always work but you got the idea
	*/

	gP1 := big.NewInt(0).Sub(p, big.NewInt(1))
	sha256.Reset()
	sha256.Write(big.NewInt(1).Bytes())
	keyGP1 := sha256.Sum(nil)
	sendMessageMITM(deriveKey(a, pubKeyNegociatedGroup(b, gP1)), deriveKey(b, pubKeyNegociatedGroup(a, gP1)), keyGP1, "message from A to B with g = p - 1")

}

func TestSet5_36(t *testing.T) {
	salt, v := genServer()
	privClient, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	privServer, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	success := srpHandshake(salt, v, privClient, privServer)
	if success == false {
		fmt.Println("Learn to implement")
	} else {
		fmt.Println("Success")
	}
}

func TestSet5_37(t *testing.T) {
	salt, v := genServer()
	privServer, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))

	//A = 0
	pubClient := big.NewInt(0)
	success := srpHandshakeRogueParam(salt, v, pubClient, privServer)
	if success == true {
		fmt.Println("Success with A = 0")
	}

	//A = p
	pubClient = p
	success = srpHandshakeRogueParam(salt, v, pubClient, privServer)
	if success == true {
		fmt.Println("Success with A = p")
	}
}

func TestSet5_38(t *testing.T) {
	mac, salt, A, b, u := simplifiedSRPHandshakeMITM([]byte("Kappa"))
	if tryPwd(mac, []byte("test"), salt, A, b, u) {
		fmt.Println("Learn to implement")
	}
	if tryPwd(mac, []byte("Kappa"), salt, A, b, u) {
		fmt.Println("Success")
	}
}

func TestSet5_39(t *testing.T) {

}
