package tests

import (
	"context"
	"testing"
	"time"

	"github.com/oceano-dev/microservices-go-common/helpers"
	"github.com/stretchr/testify/assert"
)

func TestGetPublicKeyParams(t *testing.T) {
	// CleanMongoCollection(securityKeysCollection)
	requestCodeRepository.ClearCollection()

	DeleteFolder()
	helpers.CreateFolder(myConfig.Folders)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	publicKeysParams, err := managerSecurityKeys.GetPublicKeyParams(ctx)

	assert.NoError(t, err)
	assert.Greater(t, len(publicKeysParams), 0)
}

func TestGetAllPrivateKeys(t *testing.T) {
	// CleanMongoCollection(securityKeysCollection)
	requestCodeRepository.ClearCollection()
	DeleteFolder()
	helpers.CreateFolder(myConfig.Folders)

	privateKeys := managerSecurityKeys.GetAllPrivateKeys()

	assert.Greater(t, len(privateKeys), 0)
}

func TestGetNewestPrivateKey(t *testing.T) {
	// CleanMongoCollection(securityKeysCollection)
	requestCodeRepository.ClearCollection()
	DeleteFolder()
	helpers.CreateFolder(myConfig.Folders)

	privateKey := managerSecurityKeys.GetAllPrivateKeys()

	assert.NotEmpty(t, privateKey)
}
