package services

import (
	"authentication/src/models"
	repository "authentication/src/repositories/interfaces"
	"context"
	"errors"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"golang.org/x/crypto/bcrypt"
)

type AuthenticationService struct {
	userRepository repository.UserRepository
}

func NewAuthenticationService(
	userRepository repository.UserRepository,
) *AuthenticationService {
	return &AuthenticationService{
		userRepository: userRepository,
	}
}

func (service *AuthenticationService) GetUsersWithClaim(ctx context.Context, email string, page int, size int) ([]*models.User, error) {
	return service.userRepository.GetUsersWithClaim(ctx, email, page, size)
}

func (service *AuthenticationService) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	return service.userRepository.FindByEmail(ctx, email)
}

func (service *AuthenticationService) FindByID(ctx context.Context, ID primitive.ObjectID) (*models.User, error) {
	return service.userRepository.FindByID(ctx, ID)
}

func (service *AuthenticationService) Create(ctx context.Context, user *models.User) (*models.User, error) {
	userExists, _ := service.FindByEmail(ctx, user.Email)
	if userExists != nil {
		userExists.Password = ""
		return userExists, errors.New("user exists")
	}

	user.ID = primitive.NewObjectID()

	hashedPassword, err := generateHashPassword(user.Password)
	if err != nil {
		return nil, err
	}
	user.Password = hashedPassword

	err = service.userRepository.Create(ctx, user)
	if err != nil {
		return nil, err
	}

	user.Password = ""

	return user, nil
}

func (service *AuthenticationService) UpdateEmail(ctx context.Context, user *models.User) (*models.User, error) {
	otherUser, _ := service.userRepository.FindByEmail(ctx, user.Email)
	if otherUser != nil && otherUser.ID != user.ID {
		return nil, errors.New("there is another user with the same email")
	}

	user, err := service.userRepository.UpdateEmail(ctx, user)
	if err != nil {
		return nil, errors.New("user not found")
	}

	return user, nil
}

func (service *AuthenticationService) UpdatePassword(ctx context.Context, user *models.User) (*models.User, error) {
	if user.Password == "" {
		return nil, errors.New("password is required")
	}

	hashedPassword, err := generateHashPassword(user.Password)
	if err != nil {
		return nil, err
	}
	user.Password = hashedPassword

	user, err = service.userRepository.UpdatePassword(ctx, user)
	if err != nil {
		return nil, errors.New("user not found")
	}

	return user, nil
}

func (service *AuthenticationService) UpdateClaims(ctx context.Context, user *models.User) (*models.User, error) {
	user, err := service.userRepository.UpdateClaims(ctx, user)
	if err != nil {
		return nil, errors.New("user not found")
	}

	return user, nil
}

func (service *AuthenticationService) Delete(ctx context.Context, ID primitive.ObjectID) error {
	return service.userRepository.Delete(ctx, ID)
}

func generateHashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}
