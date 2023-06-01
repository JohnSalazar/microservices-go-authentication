package dtos

import (
	"go.mongodb.org/mongo-driver/bson/primitive"

	common_models "github.com/oceano-dev/microservices-go-common/models"
)

type UserCredentials struct {
	Id      primitive.ObjectID     `json:"id"`
	Email   string                 `json:"email"`
	Claims  []common_models.Claims `json:"claims"`
	Version uint                   `json:"version"`
}
