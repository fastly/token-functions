package main

import (
	"bytes"
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

func simpleHTTPGet(url string) (responseBody string) {
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Fatal(err)
	}

	return string(body)
}

func main() {
	encodedkey := "RmFzdGx5IFRva2VuIFRlc3Q="
	interval := 60

	key, _ := base64.StdEncoding.DecodeString(encodedkey)

	number := new(bytes.Buffer)
	binary.Write(number, binary.LittleEndian, uint64(time.Now().Unix()/int64(interval)))

	mac := hmac.New(sha256.New, key)
	mac.Write(number.Bytes())
	digest := mac.Sum(nil)

	token := base64.StdEncoding.EncodeToString([]byte(digest))

	fastlyToken := simpleHTTPGet("http://token.fastly.com/token")
	validation := simpleHTTPGet("http://token.fastly.com/?" + token)

	fmt.Println("Your Token:   ", token)
	fmt.Println("Fastly Token: ", fastlyToken)
	fmt.Println("Validation:   ", validation)
}