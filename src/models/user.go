package models

import (
	//"authentication/src/helpers"
	"time"

	common_models "github.com/JohnSalazar/microservices-go-common/models"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID        primitive.ObjectID     `bson:"_id" json:"id,omitempty"`
	Email     string                 `bson:"email" json:"email,omitempty"`
	Password  string                 `bson:"password" json:"password,omitempty"`
	Claims    []common_models.Claims `bson:"claims" json:"claims,omitempty"`
	CreatedAt time.Time              `bson:"created_at" json:"created_at,omitempty"`
	UpdatedAt time.Time              `bson:"updated_at" json:"updated_at,omitempty"`
	Version   uint                   `bson:"version" json:"version" validate:"required"`
	Deleted   bool                   `bson:"deleted" json:"deleted,omitempty"`
}
