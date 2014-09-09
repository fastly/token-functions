package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

func main() {
	encodedkey := "RmFzdGx5IFRva2VuIFRlc3Q="
	var interval int64 = 60

	secret, err := base64.StdEncoding.DecodeString(encodedkey)
	if err != nil {
		log.Fatal("error base64 decoding:", err)
	}
	key := []byte(secret)

	number := Int64bytes(time.Now().Unix() / interval)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(number))

	token := base64.StdEncoding.EncodeToString(h.Sum(nil))

	response := FetchUrl("http://token.fastly.com/token")
	validation := FetchUrl("http://token.fastly.com?" + token)

	fmt.Println("Your Token:   ", token)
	fmt.Println("Fastly Token: ", response)
	fmt.Println("Validation:   ", validation)
}

func Int64bytes(int int64) []byte {
	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, uint64(int))
	return bytes
}

func FetchUrl(url string) string {
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal("error fetching url ", url, ": ", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("error reading body of http response: ", err)
	}
	return string(body)
}