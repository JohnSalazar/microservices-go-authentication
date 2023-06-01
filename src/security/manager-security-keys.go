package security

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"authentication/src/models"
	"authentication/src/services"

	trace "github.com/oceano-dev/microservices-go-common/trace/otel"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/oceano-dev/microservices-go-common/config"
	common_models "github.com/oceano-dev/microservices-go-common/models"

	"github.com/lestrrat-go/jwx/jwk"
)

var (
	keys               []*models.ECDSAPrivateKey
	newestPrivateKey   *models.ECDSAPrivateKey
	refreshPrivateKeys = time.Now()
)

type managerSecurityKeys struct {
	config  *config.Config
	service *services.SecurityKeysService
}

func NewManagerSecurityKeys(
	config *config.Config,
	service *services.SecurityKeysService,
) *managerSecurityKeys {
	return &managerSecurityKeys{
		config:  config,
		service: service,
	}
}

func (m *managerSecurityKeys) GetAllPublicKeys() []*common_models.ECDSAPublicKey {
	modelsPrivateKeys := m.GetAllPrivateKeys()

	var publicKeys []*common_models.ECDSAPublicKey

	for _, model := range modelsPrivateKeys {
		modelPublicKey := &common_models.ECDSAPublicKey{
			Key:       &model.PrivateKey.PublicKey,
			Kid:       model.Kid,
			ExpiresAt: model.ExpiresAt,
		}

		publicKeys = append(publicKeys, modelPublicKey)
	}

	return publicKeys
}

func (m *managerSecurityKeys) GetPublicKeyParams(ctx context.Context) ([]*common_models.ECDSAPublicKeysParams, error) {
	ctx, span := trace.NewSpan(ctx, "managerSecurityKeys.getPublicKeyParams")
	defer span.End()

	var publicKeysParams []*common_models.ECDSAPublicKeysParams

	modelsPrivateKeys := m.GetAllPrivateKeys()

	for _, model := range modelsPrivateKeys {
		buf, err := m.generatePublicKeyParams(ctx, &model.PrivateKey.PublicKey)
		if err != nil {
			return nil, err
		}

		var params map[string]string
		json.Unmarshal([]byte(buf), &params)

		publicKeyParams := &common_models.ECDSAPublicKeysParams{
			Alg:       model.Alg,
			Kid:       model.Kid,
			Use:       model.Use,
			ExpiresAt: model.ExpiresAt,
			Params:    params,
		}

		publicKeysParams = append(publicKeysParams, publicKeyParams)
	}

	return publicKeysParams, nil
}

func (m *managerSecurityKeys) GetAllPrivateKeys() []*models.ECDSAPrivateKey {
	if keys == nil {
		newestPrivateKey = m.GetNewestPrivateKey()
	}

	return keys
}

func (m *managerSecurityKeys) GetNewestPrivateKey() *models.ECDSAPrivateKey {
	var err error
	if newestPrivateKey == nil {
		newestPrivateKey, _ = m.getNewestPrivateKeys()
		m.refreshPrivateKeys()
	}

	if newestPrivateKey == nil {
		newestPrivateKey, err = m.generatePrivateKey()
		if err != nil {
			return nil
		}

		m.refreshPrivateKeys()

		return newestPrivateKey
	}

	privateKeysRefresh := refreshPrivateKeys.Before(time.Now().UTC())
	if privateKeysRefresh {
		newestPrivateKey, err = m.getNewestPrivateKeys()
		if err != nil {
			newestPrivateKey = &models.ECDSAPrivateKey{}
			return nil
		}

		m.refreshPrivateKeys()
		fmt.Println("refresh private keys")
	}

	privateKeyExpires := newestPrivateKey.ExpiresAt.Before(time.Now().UTC())
	if privateKeyExpires {
		newestPrivateKey, err = m.generatePrivateKey()
		if err != nil {
			return nil
		}

		m.refreshPrivateKeys()
	}

	return newestPrivateKey
}

func (m *managerSecurityKeys) getNewestPrivateKeys() (*models.ECDSAPrivateKey, error) {
	modelPrivateKey, err := m.loadJWTKeys()
	if err != nil {
		return nil, err
	}

	// if modelPrivateKey == nil {
	// 	modelPrivateKey, err = m.generatePrivateKey()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// }

	return modelPrivateKey, nil
}

func (m *managerSecurityKeys) loadJWTKeys() (*models.ECDSAPrivateKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	modelsPrivateKeys, err := m.service.GetPrivateKeysParams(ctx)
	if err != nil {
		return nil, err
	}

	if modelsPrivateKeys == nil {
		return nil, nil
	}

	for _, model := range modelsPrivateKeys {
		modelPrivateKey, err := m.convertModelToPrivateKey(model)
		if err != nil {
			return nil, err
		}
		keys = append(keys, modelPrivateKey)
	}

	return keys[0], nil
}

func (m *managerSecurityKeys) convertModelToPrivateKey(privateKeysParams *models.ECDSAPrivateKeysParams) (*models.ECDSAPrivateKey, error) {
	jwkstr, err := json.Marshal(privateKeysParams.Params)
	if err != nil {
		return nil, err
	}

	key := jwk.NewECDSAPrivateKey()
	if err := json.Unmarshal(jwkstr, key); err != nil {
		return nil, err
	}

	privateKey := &ecdsa.PrivateKey{}
	if err := key.Raw(privateKey); err != nil {
		return nil, err
	}

	modelPrivateKey := &models.ECDSAPrivateKey{
		PrivateKey: privateKey,
		Alg:        privateKeysParams.Alg,
		Kid:        privateKeysParams.Params["kid"],
		Use:        privateKeysParams.Use,
		ExpiresAt:  privateKeysParams.ExpiresAt,
	}

	return modelPrivateKey, nil
}

func (m *managerSecurityKeys) generatePrivateKey() (*models.ECDSAPrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	jwkKey, buf, err := m.generatePrivateKeyParams(privateKey)
	if err != nil {
		return nil, err
	}

	var params map[string]string
	json.Unmarshal([]byte(buf), &params)

	modelPrivateKeysParams := &models.ECDSAPrivateKeysParams{
		ID:        primitive.NewObjectID(),
		Alg:       "ES256",
		ExpiresAt: time.Now().UTC().Add(time.Duration(24*m.config.SecurityKeys.DaysToExpireKeys) * time.Hour),
		Use:       "sig",
		Params:    params,
	}

	modelPrivateKeysParams, err = m.storePrivateKeyParamsInDB(modelPrivateKeysParams)
	if err != nil {
		return nil, err
	}

	if m.config.SecurityKeys.SavePublicKeyToFile {
		err = m.createPublicKeyECFile(&privateKey.PublicKey)
		if err != nil {
			return nil, err
		}
	}

	modelPrivateKey := &models.ECDSAPrivateKey{
		PrivateKey: privateKey,
		Alg:        modelPrivateKeysParams.Alg,
		Kid:        jwkKey.KeyID(),
		Use:        modelPrivateKeysParams.Use,
		ExpiresAt:  modelPrivateKeysParams.ExpiresAt,
	}

	if keys != nil {
		keys = append(keys, nil)
		copy(keys[1:], keys)
		keys[0] = modelPrivateKey
	} else {
		keys = append(keys, modelPrivateKey)
	}

	return modelPrivateKey, nil
}

func (m *managerSecurityKeys) generatePrivateKeyParams(privateKey *ecdsa.PrivateKey) (jwk.Key, []byte, error) {
	jwkKey, err := jwk.New(privateKey)
	if err != nil {
		return nil, nil, err
	}

	if _, ok := jwkKey.(jwk.ECDSAPrivateKey); !ok {
		return nil, nil, errors.New("error jwk.ECDSAPrivateKey")
	}

	jwk.AssignKeyID(jwkKey)

	buf, err := json.MarshalIndent(jwkKey, "", " ")
	if err != nil {
		return nil, nil, err
	}

	return jwkKey, buf, nil
}

func (m *managerSecurityKeys) storePrivateKeyParamsInDB(modelPrivateKeysParams *models.ECDSAPrivateKeysParams) (*models.ECDSAPrivateKeysParams, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	privateKeys, err := m.service.CreatePrivateKeysParams(ctx, modelPrivateKeysParams)

	return privateKeys, err
}

func (m *managerSecurityKeys) createPublicKeyECFile(publicKey *ecdsa.PublicKey) error {
	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
	publicBs := pem.EncodeToMemory(&pem.Block{Type: "EC PUBLIC KEY", Bytes: x509EncodedPub})
	publicKeyFile, err := os.Create(m.config.SecurityKeys.FileECPPublicKey)
	if err != nil {
		os.Exit(1)
		return errors.New("invalid file path for Public key")
	}
	_, err = publicKeyFile.Write(publicBs)
	if err != nil {
		os.Exit(1)
		return fmt.Errorf("error when write file %s: %s \n", m.config.SecurityKeys.FileECPPublicKey, err)
	}

	return nil
}

func (m *managerSecurityKeys) refreshPrivateKeys() {
	refreshPrivateKeys = time.Now().UTC().Add(time.Minute * time.Duration(m.config.SecurityKeys.MinutesToRefreshPrivateKeys))
}

func (m *managerSecurityKeys) generatePublicKeyParams(ctx context.Context, publicKey *ecdsa.PublicKey) ([]byte, error) {
	_, span := trace.NewSpan(ctx, "managerSecurityKeys.generatePublicKeyParams")
	defer span.End()

	jwkKey, err := jwk.New(publicKey)
	if err != nil {
		return nil, err
	}

	if _, ok := jwkKey.(jwk.ECDSAPublicKey); !ok {
		return nil, errors.New("error jwk.ECDSAPublicKey")
	}

	buf, err := json.MarshalIndent(jwkKey, "", " ")
	if err != nil {
		return nil, err
	}
	return buf, nil
}
