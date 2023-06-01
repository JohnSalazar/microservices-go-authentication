package mocks

import (
	"context"
	"time"

	"authentication/src/models"
)

var securityKeys []*models.ECDSAPrivateKeysParams

type SecurityKeysRepositoryMock struct{}

func NewSecurityKeysRepositoryMock() *SecurityKeysRepositoryMock {
	return &SecurityKeysRepositoryMock{}
}

func (r *SecurityKeysRepositoryMock) ClearCollection() {
	securityKeys = []*models.ECDSAPrivateKeysParams{}
}

func (r *SecurityKeysRepositoryMock) find(securityKeysParams *models.ECDSAPrivateKeysParams) *models.ECDSAPrivateKeysParams {
	for _, securityKey := range securityKeys {
		if securityKey.ID == securityKeysParams.ID {
			return securityKey
		}
	}

	return nil
}

func (r *SecurityKeysRepositoryMock) findMany() []*models.ECDSAPrivateKeysParams {
	var params []*models.ECDSAPrivateKeysParams
	for _, securityKey := range securityKeys {
		if securityKey.ExpiresAt.After(time.Now().UTC()) {
			params = append(params, securityKey)
		}
	}

	return params
}

func (r *SecurityKeysRepositoryMock) GetPrivateKeysParams(ctx context.Context) ([]*models.ECDSAPrivateKeysParams, error) {
	params := r.findMany()

	return params, nil
}

func (r *SecurityKeysRepositoryMock) CreatePrivateKeysParams(ctx context.Context, securityKeysParams *models.ECDSAPrivateKeysParams) error {
	if r.find(securityKeysParams) == nil {
		securityKeys = append(securityKeys, securityKeysParams)
	}

	return nil
}

func (r *SecurityKeysRepositoryMock) DeletePrivateKeysParams(ctx context.Context) error {
	securityKeys = r.findMany()

	return nil
}
