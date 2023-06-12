package services

import (
	"context"

	"authentication/src/models"
	repository "authentication/src/repositories/interfaces"

	"github.com/JohnSalazar/microservices-go-common/config"
)

type SecurityKeysService struct {
	config                 *config.Config
	securityKeysRepository repository.SecurityKeysRepository
}

func NewSecurityKeysService(
	config *config.Config,
	securityKeysRepository repository.SecurityKeysRepository,
) *SecurityKeysService {
	return &SecurityKeysService{
		config:                 config,
		securityKeysRepository: securityKeysRepository,
	}
}

func (service *SecurityKeysService) GetPrivateKeysParams(ctx context.Context) ([]*models.ECDSAPrivateKeysParams, error) {
	return service.securityKeysRepository.GetPrivateKeysParams(ctx)
}

func (service *SecurityKeysService) CreatePrivateKeysParams(ctx context.Context, securityKeys *models.ECDSAPrivateKeysParams) (*models.ECDSAPrivateKeysParams, error) {
	_ = service.securityKeysRepository.DeletePrivateKeysParams(ctx)

	err := service.securityKeysRepository.CreatePrivateKeysParams(ctx, securityKeys)
	if err != nil {
		return nil, err
	}

	return securityKeys, nil
}

func (service *SecurityKeysService) DeletePrivateKeysParams(ctx context.Context) error {
	return service.securityKeysRepository.DeletePrivateKeysParams(ctx)
}
