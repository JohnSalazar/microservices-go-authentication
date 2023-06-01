package repositories

import (
	"authentication/src/models"
	"context"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type UserRepository interface {
	GetUsersWithClaim(ctx context.Context, email string, page int, size int) ([]*models.User, error)
	FindByEmail(ctx context.Context, email string) (*models.User, error)
	FindByID(ctx context.Context, ID primitive.ObjectID) (*models.User, error)
	Create(ctx context.Context, user *models.User) error
	UpdateEmail(ctx context.Context, user *models.User) (*models.User, error)
	UpdatePassword(ctx context.Context, user *models.User) (*models.User, error)
	UpdateClaims(ctx context.Context, user *models.User) (*models.User, error)
	Delete(ctx context.Context, ID primitive.ObjectID) error
}
