package main

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var key = make([]byte, 16)
var keyLen, _ = rand.Read(key)

func handler(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.URL.RequestURI())
	if err != nil {
		panic(err)
	}
	m, _ := url.ParseQuery(u.RawQuery)
	file, fileOk := m["file"]
	signature, sigOk := m["signature"]
	if fileOk == true && sigOk == true {
		genSig := computeHMAC([]byte(file[0]))
		receivedSig := parseSignature(signature[0])
		isValid := insecureCompare(genSig, receivedSig)
		if isValid == true {
			w.WriteHeader(200)
			w.Write([]byte("OK"))
		} else {
			w.WriteHeader(500)
			w.Write([]byte("Wrong signature"))
		}

	} else {
		w.WriteHeader(500)
		w.Write([]byte("Wrong URL format"))
	}
}

func parseSignature(signature string) []byte {
	signature = strings.Replace(signature, "-", "+", -1)
	signature = strings.Replace(signature, "_", "/", -1)
	if len(signature)%4 == 2 {
		signature += "=="
	} else if len(signature)%4 == 3 {
		signature += "="
	}
	parsed, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		fmt.Println(err)
	}
	return parsed
}

func computeHMAC(file []byte) []byte {
	sha1 := sha1.New()
	paddedKey := append(key, make([]byte, sha1.BlockSize()-keyLen)...)
	opad := []byte(strings.Repeat("5c", sha1.BlockSize()/2))
	ipad := []byte(strings.Repeat("36", sha1.BlockSize()/2))
	iKey := make([]byte, sha1.BlockSize())
	oKey := make([]byte, sha1.BlockSize())
	for i := range paddedKey {
		iKey[i] = paddedKey[i] ^ ipad[i]
		oKey[i] = paddedKey[i] ^ opad[i]
	}
	sha1.Write(append(iKey, file...))
	hash := sha1.Sum(nil)
	sha1.Write(append(oKey, hash...))
	return sha1.Sum(nil)
}

func insecureCompare(provenSig []byte, receivedSig []byte) bool {
	for i := range provenSig {
		time.Sleep(time.Duration(2) * time.Millisecond)
		if provenSig[i] != receivedSig[i] {
			return false
		}
	}
	return true
}

func main() {
	http.HandleFunc("/test", handler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
