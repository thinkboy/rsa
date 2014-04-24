package main

// #include <stdlib.h>
// #include <string.h>
// #include "rsa.h"
// #cgo LDFLAGS: -lcrypto
import "C"
import (
	"fmt"
)

var publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC2kcrRvxURhFijDoPpqZ/IgPlAgppkKrek6wSrua1zBiGTwHI2f+YCa5vC1JEiIi9uw4srS0OSCB6kY3bP2DGJagBoEgj/rYAGjtYJxJrEiTxVs5/GfPuQBYmU0XAtPXFzciZy446VPJLHMPnmTALmIOR5Dddd1Zklod9IQBMjjwIDAQAB"
var content = "JxRV2nULc/2iJYP5w5Ilo9k/gJwM79Aq/S7sb1hfvNWQGsaU7iaoCxcc4bMdVVS3bq9SuroizCdPbz+bEb+o6HrGgy65IFf7A6VHQ1j27LYRQHHSUvKFpYPBNCR8sV4cvWXvG5onSzWxzwMiKS5D1EOYgcLad/pd9ruJ+O4K2wMjMKLBCjLZCrwdkizhHl4LbhOPIlGuysZBK+mKL0XcFEE8n+DGOJKJxU0n3mfSCRs2kkwFkWoUw16IBtti4CLUnRccMwnHsuvBPyngfRkskft5nVaBu9ntaEa2SiEGsQRMZqpQmfiBbIwZyzR2lqGrCdq7QKNYKk5MagXgY98x+Q=="

func main() {
	// Decrypt
	pukey := C.CString(publicKey)
	cont := C.CString(content)
	plaintext := C.RSAPublicDecrypt(C.CString(publicKey), C.CString(content))
	plaintextStr := C.GoString(plaintext)
	C.free(unsafe.Pointer(pukey))
	C.free(unsafe.Pointer(cont))
	plaintextStr := C.GoString(plaintext)
	if plaintext != nil {
		C.free(unsafe.Pointer(plaintext))
	}
	if plaintextStr == "" {
		panic("RSA PublicKey Decrypt failed")
	}

	fmt.Println(fmt.Sprintf("plaintext:%s", plaintextStr))
}
