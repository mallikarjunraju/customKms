// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package plugin

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"

	"crypto/aes"
	"crypto/cipher"

	"github.com/Azure/kubernetes-kms/pkg/auth"
	"github.com/Azure/kubernetes-kms/pkg/config"
	"github.com/Azure/kubernetes-kms/pkg/utils"
	"github.com/Azure/kubernetes-kms/pkg/version"

	kv "github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/Azure/go-autorest/autorest/azure"
	"k8s.io/klog/v2"
)

// Client interface for interacting with Keyvault
type Client interface {
	Encrypt(ctx context.Context, cipher []byte) ([]byte, error)
	Decrypt(ctx context.Context, plain []byte) ([]byte, error)
}

type keyVaultClient struct {
	baseClient       kv.BaseClient
	config           *config.AzureConfig
	vaultName        string
	keyName          string
	keyVersion       string
	vaultURL         string
	azureEnvironment *azure.Environment
}

// NewKeyVaultClient returns a new key vault client to use for kms operations
func newKeyVaultClient(config *config.AzureConfig, vaultName, keyName, keyVersion string) (*keyVaultClient, error) {
	// Sanitize vaultName, keyName, keyVersion. (https://github.com/Azure/kubernetes-kms/issues/85)
	vaultName = utils.SanitizeString(vaultName)
	keyName = utils.SanitizeString(keyName)
	keyVersion = utils.SanitizeString(keyVersion)

	// this should be the case for bring your own key, clusters bootstrapped with
	// aks-engine or aks and standalone kms plugin deployments
	if len(vaultName) == 0 || len(keyName) == 0 || len(keyVersion) == 0 {
		return nil, fmt.Errorf("key vault name, key name and key version are required")
	}
	kvClient := kv.New()
	err := kvClient.AddToUserAgent(version.GetUserAgent())
	if err != nil {
		return nil, fmt.Errorf("failed to add user agent to keyvault client, error: %+v", err)
	}
	env, err := auth.ParseAzureEnvironment(config.Cloud)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cloud environment: %s, error: %+v", config.Cloud, err)
	}
	token, err := auth.GetKeyvaultToken(config, env)
	if err != nil {
		return nil, fmt.Errorf("failed to get key vault token, error: %+v", err)
	}
	kvClient.Authorizer = token

	vaultURL, err := getVaultURL(vaultName, env)
	if err != nil {
		return nil, fmt.Errorf("failed to get vault url, error: %+v", err)
	}

	klog.InfoS("using kms key for encrypt/decrypt", "vaultName", vaultName, "keyName", keyName, "keyVersion", keyVersion)

	client := &keyVaultClient{
		baseClient:       kvClient,
		config:           config,
		vaultName:        vaultName,
		keyName:          keyName,
		keyVersion:       keyVersion,
		vaultURL:         *vaultURL,
		azureEnvironment: env,
	}
	return client, nil
}

func (kvc *keyVaultClient) Encrypt(ctx context.Context, cipher []byte) ([]byte, error) {
	value := base64.RawURLEncoding.EncodeToString(cipher)
	klog.InfoS("cipher value:", value)

	nresult, err := encrypt(ctx, cipher)
	klog.InfoS("nresult value:", nresult)

	if err != nil {
		return nil, fmt.Errorf("failed to encrypt, error: %+v", err)
	}

	return nresult, nil
}

func (kvc *keyVaultClient) Decrypt(ctx context.Context, plain []byte) ([]byte, error) {
	kresult, err2 := decrypt(ctx, plain)
	if err2 != nil {
		return nil, fmt.Errorf("failed to encrypt, error: %+v", err2)
	}
	klog.InfoS("kresult value:", kresult)
	return kresult, nil
}

func getVaultURL(vaultName string, azureEnvironment *azure.Environment) (vaultURL *string, err error) {
	// Key Vault name must be a 3-24 character string
	if len(vaultName) < 3 || len(vaultName) > 24 {
		return nil, fmt.Errorf("invalid vault name: %q, must be between 3 and 24 chars", vaultName)
	}

	// See docs for validation spec: https://docs.microsoft.com/en-us/azure/key-vault/about-keys-secrets-and-certificates#objects-identifiers-and-versioning
	isValid := regexp.MustCompile(`^[-A-Za-z0-9]+$`).MatchString
	if !isValid(vaultName) {
		return nil, fmt.Errorf("invalid vault name: %q, must match [-a-zA-Z0-9]{3,24}", vaultName)
	}

	vaultDNSSuffixValue := azureEnvironment.KeyVaultDNSSuffix
	vaultURI := "https://" + vaultName + "." + vaultDNSSuffixValue + "/"
	return &vaultURI, nil
}

func encrypt(ctx context.Context, plain []byte) ([]byte, error) {
	key := []byte("keygopostmediumkeygopostmediumke")
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
	fmt.Printf("Ciphertext: %x\n", ciphertext)

	return ciphertext, nil

}

func decrypt(ctx context.Context, plain []byte) ([]byte, error) {
	key := []byte("keygopostmediumkeygopostmediumke")
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
	fmt.Printf("Plaintext: %s\n", string(plaintext))
	return plaintext, nil
}
