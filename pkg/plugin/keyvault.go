// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package plugin

import (
	"context"
	"encoding/base64"
	"fmt"

	"crypto/aes"
	"crypto/cipher"
	"custom-kms/pkg/utils"

	"k8s.io/klog/v2"
)

// Client interface for interacting with Keyvault
type Client interface {
	Encrypt(ctx context.Context, cipher []byte) ([]byte, error)
	Decrypt(ctx context.Context, plain []byte) ([]byte, error)
}

type keyVaultClient struct {
	kekKey string
}

// NewTPMClient returns a new key for aes client to use for encryption operations
func newTPMClient(config string) (*keyVaultClient, error) {
	config = utils.SanitizeString(config)

	if len(config) == 0 {
		return nil, fmt.Errorf("config is required")
	}
	// Get this Key(32-bit) from TPM
	kekKey := "zthisisthetpmsecretencryptionkey"
	client := &keyVaultClient{
		kekKey: kekKey,
	}
	klog.InfoS("using kms key for encrypt/decrypt", "kekKey", kekKey)

	return client, nil
}

func (kvc *keyVaultClient) Encrypt(ctx context.Context, cipher []byte) ([]byte, error) {
	value := base64.RawURLEncoding.EncodeToString(cipher)
	klog.InfoS("cipher value:", value)

	nresult, err := AESEncryption(ctx, kvc.kekKey, cipher)
	klog.InfoS("nresult value:", nresult)

	if err != nil {
		return nil, fmt.Errorf("failed to encrypt, error: %+v", err)
	}

	return nresult, nil
}

func (kvc *keyVaultClient) Decrypt(ctx context.Context, plain []byte) ([]byte, error) {
	kresult, err2 := AESDecryption(ctx, kvc.kekKey, plain)
	if err2 != nil {
		return nil, fmt.Errorf("failed to encrypt, error: %+v", err2)
	}
	klog.InfoS("kresult value:", kresult)
	return kresult, nil
}
func AESEncryption(ctx context.Context, _key string, plain []byte) ([]byte, error) {
	key := []byte(_key)
	plaintext := plain
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, aesGCM.NonceSize())

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	fmt.Printf("My custom Ciphertext: %x\n", ciphertext)

	return ciphertext, nil

}

func AESDecryption(ctx context.Context, _key string, plain []byte) ([]byte, error) {
	key := []byte(_key)
	ciphertext := plain
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("My custom Plaintext: %s\n", string(plaintext))
	return plaintext, nil
}
