package mocks

import (
	"context"
	"errors"
	"strings"

	"authentication/src/models"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

var usersList []models.User

type UserRepositoryMock struct{}

func NewUserRepositoryMock() *UserRepositoryMock {
	return &UserRepositoryMock{}
}

func (r *UserRepositoryMock) ClearCollection() {
	usersList = []models.User{}
}

func (r *UserRepositoryMock) find(userModel *models.User) (*models.User, int) {
	for i, user := range usersList {
		if user.ID == userModel.ID && user.Version == userModel.Version {
			return &user, i
		}
	}

	return nil, -1
}

func (r *UserRepositoryMock) GetUsersWithClaim(ctx context.Context, email string, page int, size int) ([]*models.User, error) {
	var withClaim []*models.User

	for _, user := range usersList {
		if len(email) > 0 {
			if strings.Contains(user.Email, email) {
				if len(user.Claims) > 0 {
					withClaim = append(withClaim, &user)
				}
			}
		} else {
			if len(user.Claims) > 0 {
				withClaim = append(withClaim, &user)
			}
		}

		if len(withClaim) >= size {
			return withClaim, nil
		}
	}

	return withClaim, nil
}

func (r *UserRepositoryMock) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	for _, user := range usersList {
		if user.Email == email {
			return &user, nil
		}
	}

	return nil, errors.New("user not found")
}

func (r *UserRepositoryMock) FindByID(ctx context.Context, ID primitive.ObjectID) (*models.User, error) {
	for _, user := range usersList {
		if user.ID == ID {
			return &user, nil
		}
	}

	return nil, errors.New("user not found")
}

func (r *UserRepositoryMock) Create(ctx context.Context, user *models.User) error {
	userModel, _ := r.find(user)
	if userModel == nil {
		newUser := *user
		usersList = append(usersList, newUser)
	}

	return nil
}

func (r *UserRepositoryMock) UpdateEmail(ctx context.Context, user *models.User) (*models.User, error) {
	userModel, index := r.find(user)
	if userModel == nil {
		return nil, errors.New("user not found")
	}

	// updatedUser := *userModel
	userModel.Email = user.Email
	userModel.Version = user.Version + 1
	usersList[index] = *userModel

	return userModel, nil
}

func (r *UserRepositoryMock) UpdatePassword(ctx context.Context, user *models.User) (*models.User, error) {
	userModel, index := r.find(user)
	if userModel == nil {
		return nil, errors.New("user not found")
	}

	updatedUser := *userModel
	userModel.Password = user.Password
	userModel.Version = user.Version + 1
	usersList[index] = updatedUser

	return &updatedUser, nil
}

func (r *UserRepositoryMock) UpdateClaims(ctx context.Context, user *models.User) (*models.User, error) {
	userModel, index := r.find(user)
	if userModel == nil {
		return nil, errors.New("user not found")
	}

	// updatedUser := *userModel
	userModel.Claims = user.Claims
	userModel.Version = user.Version + 1
	usersList[index] = *userModel

	return userModel, nil
}

func (r *UserRepositoryMock) Delete(ctx context.Context, ID primitive.ObjectID) error {
	for i, user := range usersList {
		if user.ID == ID {
			usersList = append(usersList[:i], usersList[i+1:]...)
			return nil
		}
	}

	return errors.New("user not found")
}
