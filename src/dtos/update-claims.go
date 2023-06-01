package dtos

import common_models "github.com/oceano-dev/microservices-go-common/models"

type UpdateClaims struct {
	ID      string                 `json:"id"`
	Claims  []common_models.Claims `json:"claims,omitempty"`
	Version uint                   `json:"version"`
}
