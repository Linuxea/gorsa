package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
)

//go:embed private
var privateKey string

//go:embed public
var publicKey string

func main() {

	data := "今天是个好日子好呀好日子"
	sign, err := sign([]byte(data))
	if err != nil {
		panic(err.Error())
	}

	fmt.Println("signature", string(sign))

	err2 := verify([]byte(data), sign)
	if err != nil {
		panic(err2.Error())
	}

	fmt.Println("验证结果", err2)

}

func sign(data []byte) ([]byte, error) {

	pk, err := ParsePKCS1PrivateKey([]byte(privateKey))
	if err != nil {
		return nil, err
	}

	var h = crypto.SHA1.New()
	h.Write(data)
	var hashed = h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, pk, crypto.SHA1, hashed)
}

func verify(data, signature []byte) error {

	pub, err := ParsePKCS1PublicKey([]byte(publicKey))
	if err != nil {
		return err
	}

	var h = crypto.SHA1.New()
	h.Write(data)
	var hashed = h.Sum(nil)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA1, hashed, signature)

}

func ParsePKCS1PrivateKey(data []byte) (key *rsa.PrivateKey, err error) {
	var block *pem.Block
	block, _ = pem.Decode(data)
	if block == nil {
		return nil, errors.New("private key error")
	}

	key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, err
}

func ParsePKCS1PublicKey(data []byte) (key *rsa.PublicKey, err error) {
	var block *pem.Block
	block, _ = pem.Decode(data)
	if block == nil {
		return nil, errors.New("public key error")
	}

	var pubInterface interface{}
	pubInterface, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key error")
	}

	return key, err
}
