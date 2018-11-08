package cryptochallenges

import (
	"crypto"
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"math/big"
)

var p, _ = new(big.Int).SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
var g = big.NewInt(2)

func computePublicKey(priv *big.Int) *big.Int {
	priv.Mod(priv, p)
	pub := big.NewInt(0)
	pub.Exp(g, priv, p)
	return pub
}

func deriveKey(priv *big.Int, pub *big.Int) []byte {
	var s big.Int
	s.Exp(pub, priv, p)
	sha256 := crypto.SHA256.New()
	return sha256.Sum(s.Bytes())
}

func sendMessageMITM(keyA []byte, keyB []byte, keyM []byte, message string) {
	fmt.Printf("This is A sending the message : %s\n", message)
	blockA, err := aes.NewCipher(keyA[:16])
	if err != nil {
		fmt.Println(err)
	}
	IV := make([]byte, 16)
	rand.Read(IV)
	encryptedA := encryptCBC([]byte(message), blockA, IV)
	toSendA := append(IV, encryptedA...)
	fmt.Println("This is M getting the message")
	blockM, err := aes.NewCipher(keyM[:16])
	if err != nil {
		fmt.Println(err)
	}
	decryptedM := decryptCBC(toSendA[16:], blockM, toSendA[:16])
	fmt.Printf("decrypted %s\n", decryptedM)
	fmt.Println("M re-encrypting and sending to B")
	encryptedM := encryptCBC([]byte(message), blockM, toSendA[:16])
	toSendM := append(toSendA[:16], encryptedM...)
	fmt.Println("This is B getting the message")
	blockB, err := aes.NewCipher(keyB[:16])
	if err != nil {
		fmt.Println(err)
	}
	decryptedB := decryptCBC(toSendM[16:], blockB, toSendM[:16])
	fmt.Printf("decrypted %s\n", decryptedB)
}
