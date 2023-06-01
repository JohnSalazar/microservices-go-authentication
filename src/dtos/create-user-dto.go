package dtos

import common_models "github.com/oceano-dev/microservices-go-common/models"

type CreateUser struct {
	Email    string                 `json:"email"`
	Password string                 `json:"password,omitempty"`
	Claims   []common_models.Claims `json:"claims,omitempty"`
}
