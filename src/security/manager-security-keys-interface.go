package security

import (
	"context"

	"authentication/src/models"

	common_models "github.com/oceano-dev/microservices-go-common/models"
)

type ManagerSecurityKeys interface {
	GetAllPublicKeys() []*common_models.ECDSAPublicKey
	GetPublicKeyParams(ctx context.Context) ([]*common_models.ECDSAPublicKeysParams, error)
	GetAllPrivateKeys() []*models.ECDSAPrivateKey
	GetNewestPrivateKey() *models.ECDSAPrivateKey
}
