package cryptochallenges

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math"
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
	sha256.Write(s.Bytes())
	return sha256.Sum(nil)
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
	decryptedM, _ := stripPaddingPKCS7(string(decryptCBC(toSendA[16:], blockM, toSendA[:16])))
	fmt.Printf("decrypted %s\n", decryptedM)
	fmt.Println("M re-encrypting and sending to B")
	encryptedM := encryptCBC([]byte(message), blockM, toSendA[:16])
	toSendM := append(toSendA[:16], encryptedM...)
	fmt.Println("This is B getting the message")
	blockB, err := aes.NewCipher(keyB[:16])
	if err != nil {
		fmt.Println(err)
	}
	decryptedB, _ := stripPaddingPKCS7(string(decryptCBC(toSendM[16:], blockB, toSendM[:16])))
	fmt.Printf("decrypted %s\n", decryptedB)
}

func pubKeyNegociatedGroup(priv *big.Int, negG *big.Int) *big.Int {
	priv.Mod(priv, p)
	pub := big.NewInt(0)
	pub.Exp(negG, priv, p)
	return pub
}

/*
Parameters for SRP
g and p will be used for group and NIST prime
*/

var k = big.NewInt(3)
var email = "foo.bar@baz.com"
var pwd = "lololol"

func hashToInteger(h []byte) *big.Int {
	return new(big.Int).SetBytes(h)
}

func genServer() (*big.Int, *big.Int) {
	salt, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		fmt.Println(err)
	}
	sha256 := crypto.SHA256.New()
	sha256.Write(salt.Bytes())
	sha256.Write([]byte(pwd))
	xH := sha256.Sum(nil)
	x := hashToInteger(xH)
	v := big.NewInt(0).Exp(g, x, p)
	return salt, v
}

func srpHandshake(salt *big.Int, v *big.Int, a *big.Int, b *big.Int) bool {
	//Client ->
	A := big.NewInt(0).Exp(g, a, p)

	//Server ->
	B := big.NewInt(0).Mul(k, v)
	B.Add(B, big.NewInt(0).Exp(g, b, p))

	//Both
	sha256 := crypto.SHA256.New()
	sha256.Write(A.Bytes())
	sha256.Write(B.Bytes())
	u := hashToInteger(sha256.Sum(nil))

	//Client ->
	SClient := computeSClient([]byte(pwd), salt.Bytes(), B, a, u)
	sha256.Reset()
	sha256.Write(SClient.Bytes())
	KClient := sha256.Sum(nil)

	//Server ->
	SServer := computeSServer(A, v, u, b)
	sha256.Reset()
	sha256.Write(SServer.Bytes())
	KServer := sha256.Sum(nil)
	if bytes.Compare(computeHMAC(KClient, salt.Bytes()), computeHMAC(KServer, salt.Bytes())) == 0 {
		return true
	}
	return false
}

func computeSClient(pwd []byte, salt []byte, B *big.Int, a *big.Int, u *big.Int) *big.Int {
	sha256 := crypto.SHA256.New()
	sha256.Write(salt)
	sha256.Write([]byte(pwd))
	xH := sha256.Sum(nil)
	x := hashToInteger(xH)
	SClient := big.NewInt(0).Mul(k, big.NewInt(0).Exp(g, x, p))
	SClient.Sub(B, SClient)
	return SClient.Exp(SClient, a.Add(a, big.NewInt(0).Mul(u, x)), p)
}

func computeSServer(A *big.Int, v *big.Int, u *big.Int, b *big.Int) *big.Int {
	SServer := big.NewInt(0).Mul(A, big.NewInt(0).Exp(v, u, p))
	return SServer.Exp(SServer, b, p)
}

func computeHMAC(K []byte, salt []byte) []byte {
	h := hmac.New(sha256.New, K)
	h.Write(salt)
	return h.Sum(nil)
}

func srpHandshakeRogueParam(salt *big.Int, v *big.Int, A *big.Int, b *big.Int) bool {

	//Server
	B := big.NewInt(0).Mul(k, v)
	B.Add(B, big.NewInt(0).Exp(g, b, p))
	sha256 := crypto.SHA256.New()
	sha256.Write(A.Bytes())
	sha256.Write(B.Bytes())
	u := hashToInteger(sha256.Sum(nil))

	//Client (doesn't need the pwd)
	SClient := big.NewInt(0)
	sha256.Reset()
	sha256.Write(SClient.Bytes())
	KClient := sha256.Sum(nil)

	//Server ->
	SServer := computeSServer(A, v, u, b)
	sha256.Reset()
	sha256.Write(SServer.Bytes())
	KServer := sha256.Sum(nil)

	if bytes.Compare(computeHMAC(KClient, salt.Bytes()), computeHMAC(KServer, salt.Bytes())) == 0 {
		return true
	}
	return false
}

func simplifiedSRPHandshakeMITM(pwd []byte) ([]byte, *big.Int, *big.Int, *big.Int, *big.Int) {
	//MITM init
	salt, _ := genServer()

	//Client ->
	a, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	A := computePublicKey(a)

	//MITM ->
	b, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	B := computePublicKey(b)
	byteU := make([]byte, 8)
	rand.Read(byteU)
	u := new(big.Int).SetBytes(byteU)

	//Client ->
	s256 := crypto.SHA256.New()
	s256.Write(salt.Bytes())
	s256.Write(pwd)
	xH := s256.Sum(nil)
	x := hashToInteger(xH)
	SClient := big.NewInt(0).Exp(B, big.NewInt(0).Add(a, big.NewInt(0).Mul(u, x)), p)
	s256.Reset()
	s256.Write(SClient.Bytes())
	K := s256.Sum(nil)
	hmac256 := hmac.New(sha256.New, K)
	hmac256.Write(salt.Bytes())
	return hmac256.Sum(nil), salt, A, b, u
}

func tryPwd(mac []byte, pwd []byte, salt *big.Int, A *big.Int, b *big.Int, u *big.Int) bool {
	B := computePublicKey(b)
	s256 := crypto.SHA256.New()
	s256.Write(salt.Bytes())
	s256.Write(pwd)
	xH := s256.Sum(nil)
	x := hashToInteger(xH)
	S := big.NewInt(0).Mul(big.NewInt(0).Exp(A, b, p), big.NewInt(0).Exp(B, big.NewInt(0).Mul(u, x), p))
	S.Mod(S, p)
	s256.Reset()
	s256.Write(S.Bytes())
	K := s256.Sum(nil)
	hmac256 := hmac.New(sha256.New, K)
	hmac256.Write(salt.Bytes())
	if bytes.Compare(hmac256.Sum(nil), mac) == 0 {
		return true
	}
	return false
}
