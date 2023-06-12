package tests

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"authentication/src/models"

	"github.com/JohnSalazar/microservices-go-common/helpers"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func TestGetPrivateKeysParamsSuccess(t *testing.T) {
	// CleanMongoCollection(securityKeysCollection)
	securityKeysRepository.ClearCollection()
	DeleteFolder()
	helpers.CreateFolder(myConfig.Folders)

	ctx, close := context.WithTimeout(context.Background(), time.Second*10)
	defer close()

	createPrivateKey(ctx)

	modelsPrivateKeys, err := securityKeysService.GetPrivateKeysParams(ctx)

	assert.NoError(t, err)
	assert.Greater(t, len(modelsPrivateKeys), 0)
}

func TestCreatePrivateKeysParamsSuccess(t *testing.T) {
	// CleanMongoCollection(securityKeysCollection)
	securityKeysRepository.ClearCollection()
	DeleteFolder()
	helpers.CreateFolder(myConfig.Folders)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	privateKeys, _ := createPrivateKey(ctx)

	_, err := json.Marshal(privateKeys)
	if err != nil {
		panic(err)
	}

	assert.NoError(t, err)
	assert.NotNil(t, privateKeys)
}

func TestDeletePrivateKeysParams(t *testing.T) {
	// CleanMongoCollection(securityKeysCollection)
	securityKeysRepository.ClearCollection()
	DeleteFolder()
	helpers.CreateFolder(myConfig.Folders)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	createPrivateKey(ctx)

	err := securityKeysService.DeletePrivateKeysParams(ctx)

	assert.NoError(t, err)
}

func createPrivateKey(ctx context.Context) (*models.ECDSAPrivateKeysParams, error) {
	modelPrivateKeysParams := &models.ECDSAPrivateKeysParams{
		ID:        primitive.NewObjectID(),
		Alg:       "ES256",
		ExpiresAt: time.Now().UTC().Add(time.Duration(24*60) * time.Hour),
		Use:       "sig",
		Params: map[string]string{
			"crv": "crv",
			"d":   "d",
			"kid": "kid",
			"kty": "kty",
			"x":   "x",
			"y":   "y",
		},
	}

	return securityKeysService.CreatePrivateKeysParams(ctx, modelPrivateKeysParams)
}
