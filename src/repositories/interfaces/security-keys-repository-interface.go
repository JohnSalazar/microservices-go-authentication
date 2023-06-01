package repositories

import (
	"context"

	"authentication/src/models"
)

type SecurityKeysRepository interface {
	GetPrivateKeysParams(ctx context.Context) ([]*models.ECDSAPrivateKeysParams, error)
	CreatePrivateKeysParams(ctx context.Context, securityKeys *models.ECDSAPrivateKeysParams) error
	DeletePrivateKeysParams(ctx context.Context) error
}
