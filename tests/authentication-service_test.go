package tests

import (
	"context"
	"testing"
	"time"

	"authentication/src/models"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"

	common_models "github.com/JohnSalazar/microservices-go-common/models"
)

func TestCreate(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	ctx, close := context.WithTimeout(context.Background(), time.Second*10)
	defer close()

	modelUser := createModelUser()

	var err error
	var userCreated *models.User

	userExists, _ := authService.FindByEmail(ctx, modelUser.Email)
	if userExists == nil {
		userCreated, err = authService.Create(ctx, modelUser)
	}

	assert.Nil(t, userExists)
	assert.Equal(t, modelUser.Email, userCreated.Email)
	assert.NoError(t, err)
}

func TestCreateErrorExistsUser(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	ctx, close := context.WithTimeout(context.Background(), time.Second*10)
	defer close()

	modelUser := createModelUser()

	userCreated, errNil := authService.Create(ctx, modelUser)

	userExists, errNotNil := authService.Create(ctx, modelUser)

	assert.Equal(t, modelUser.Email, userCreated.Email)
	assert.NoError(t, errNil)
	assert.NotNil(t, userExists)
	assert.Error(t, errNotNil)
}

func TestGetUsersWithClaim(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	ctx, close := context.WithTimeout(context.Background(), time.Second*10)
	defer close()

	modelUser := createModelUser()
	modelUser.Claims = []common_models.Claims{
		{Type: "user", Value: "read"},
	}

	_, _ = authService.Create(ctx, modelUser)

	users, _ := authService.GetUsersWithClaim(ctx, modelUser.Email, 1, 1)

	assert.Equal(t, modelUser.Email, users[0].Email)
}

func TestFindByEmail(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	ctx, close := context.WithTimeout(context.Background(), time.Second*10)
	defer close()

	modelUser := createModelUser()

	_, _ = authService.Create(ctx, modelUser)

	user, _ := authService.FindByEmail(ctx, modelUser.Email)

	assert.Equal(t, modelUser.Email, user.Email)
}

func TestFindByID(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	ctx, close := context.WithTimeout(context.Background(), time.Second*10)
	defer close()

	modelUser := createModelUser()

	userCreated, _ := authService.Create(ctx, modelUser)

	user, _ := authService.FindByID(ctx, userCreated.ID)

	assert.Equal(t, modelUser.Email, user.Email)
}

func TestUpdateEmail(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	ctx, close := context.WithTimeout(context.Background(), time.Second*10)
	defer close()

	modelUser := createModelUser()

	userCreated, _ := authService.Create(ctx, modelUser)
	userCreated.Email = "user2@gmail.com"

	user, _ := authService.UpdateEmail(ctx, userCreated)

	assert.NotNil(t, userCreated)
	assert.Equal(t, userCreated.Email, user.Email)
}

func TestUpdateEmailErrorOtherExistsUserEmail(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	ctx, close := context.WithTimeout(context.Background(), time.Second*10)
	defer close()

	modelUser := createModelUser()

	otherUser := &models.User{
		ID:    primitive.NewObjectID(),
		Email: "user2@gmail.com",
	}

	userCreated, _ := authService.Create(ctx, modelUser)
	otherUserCreated, _ := authService.Create(ctx, otherUser)

	userModelUpdateEmail := modelUser
	userModelUpdateEmail.Email = otherUserCreated.Email

	user, err := authService.UpdateEmail(ctx, userModelUpdateEmail)

	assert.NotNil(t, userCreated)
	assert.Equal(t, userModelUpdateEmail.Email, otherUserCreated.Email)
	assert.Nil(t, user)
	assert.Error(t, err)
}

func TestUpdatePassword(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	ctx, close := context.WithTimeout(context.Background(), time.Second*10)
	defer close()

	modelUser := createModelUser()

	userCreated, _ := authService.Create(ctx, modelUser)

	userCreated.Password = "newPassword"

	user, err := authService.UpdatePassword(ctx, userCreated)

	assert.NotNil(t, user)
	assert.NotEqual(t, modelUser.Password, user.Password)
	assert.NoError(t, err)
}

func TestUpdatePasswordErrorPasswordEmpty(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	ctx, close := context.WithTimeout(context.Background(), time.Second*10)
	defer close()

	modelUser := createModelUser()

	userCreated, _ := authService.Create(ctx, modelUser)

	userModelUpdatePassword := &models.User{
		ID: userCreated.ID,
	}

	user, err := authService.UpdatePassword(ctx, userModelUpdatePassword)

	assert.Nil(t, user)
	assert.Error(t, err)
}

func TestUpdateClaims(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	ctx, close := context.WithTimeout(context.Background(), time.Second*10)
	defer close()

	modelUser := createModelUser()

	userCreated, _ := authService.Create(ctx, modelUser)

	userModelUpdateClaims := &models.User{
		ID: userCreated.ID,
		Claims: []common_models.Claims{
			{Type: "user", Value: "read"},
		},
	}

	user, _ := authService.UpdateClaims(ctx, userModelUpdateClaims)

	assert.NotNil(t, user)
	assert.NotEqual(t, userCreated.Claims, user.Claims)
}

func TestUpdateClaimsErrorUserNotFound(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	ctx, close := context.WithTimeout(context.Background(), time.Second*10)
	defer close()

	modelUser := createModelUser()

	userCreated, _ := authService.Create(ctx, modelUser)

	userModelUpdateClaims := &models.User{
		ID: primitive.NewObjectID(),
		Claims: []common_models.Claims{
			{Type: "user", Value: "read"},
		},
	}

	user, err := authService.UpdateClaims(ctx, userModelUpdateClaims)

	assert.NotNil(t, userCreated)
	assert.NotEqual(t, userCreated.Claims, userModelUpdateClaims.Claims)
	assert.Nil(t, user)
	assert.Error(t, err)
}

func TestDelete(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	ctx, close := context.WithTimeout(context.Background(), time.Second*100)
	defer close()

	modelUser := createModelUser()

	userCreated, _ := authService.Create(ctx, modelUser)

	err := authService.Delete(ctx, userCreated.ID)

	assert.NotNil(t, userCreated)
	assert.Nil(t, err)
}

func TestDeleteErrorUserNotFound(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	ctx, close := context.WithTimeout(context.Background(), time.Second*100)
	defer close()

	modelUser := createModelUser()

	userModelDelete := &models.User{
		ID: primitive.NewObjectID(),
	}

	userCreated, _ := authService.Create(ctx, modelUser)

	err := authService.Delete(ctx, userModelDelete.ID)

	assert.NotNil(t, userCreated)
	assert.NotEqual(t, userCreated.ID, userModelDelete.ID)
	assert.NotNil(t, err)
}

func createModelUser() *models.User {
	modelUser := &models.User{
		Email:    "user1@gmail.com",
		Password: "P@ssw@rd",
	}

	return modelUser
}
