package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type ECDSAPrivateKeysParams struct {
	ID        primitive.ObjectID `bson:"_id" json:"id"`
	Alg       string             `bson:"alg" json:"alg"`
	Use       string             `bson:"use" json:"use"`
	ExpiresAt time.Time          `bson:"expires_at" json:"expires_at"`
	Params    map[string]string  `bson:"params" json:"params"`
}
