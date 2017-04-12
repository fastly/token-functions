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
	var interval uint64 = 60

	key, err := base64.StdEncoding.DecodeString(encodedkey)
	if err != nil {
		log.Fatalf("error base64 decoding: %s", err)
	}

	number := Int64bytes(uint64(time.Now().Unix()) / interval)
	h := hmac.New(sha256.New, key)
	h.Write(number)

	token := base64.StdEncoding.EncodeToString(h.Sum(nil))

	response := FetchURL("http://token.fastly.com/token")
	validation := FetchURL("http://token.fastly.com?" + token)

	fmt.Println("Your Token:   ", token)
	fmt.Println("Fastly Token: ", string(response))
	fmt.Println("Validation:   ", string(validation))
}

func Int64bytes(int uint64) []byte {
	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, uint64(int))
	return bytes
}

func FetchURL(url string) []byte {
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("error fetching url %s : %s", url, err)
	}
	if resp.StatusCode != 200 {
		log.Fatalf("error fetching url %s : %s", url, resp.Status)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("error reading body of http response: %s", err)
	}
	return body
}
