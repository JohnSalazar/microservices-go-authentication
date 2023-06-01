package tests

import (
	"authentication/src/models"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/stretchr/testify/assert"
)

func TestCreateAccessTokenIDReturnsError(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	user := &models.User{
		Email: "usuario1@gmail.com",
	}

	_, err := managerToken.CreateAccessToken(ctx, user)

	assert.ErrorContains(t, err, "user id is required")
}

func TestCreateAccessTokenEmailReturnsError(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	user := &models.User{
		ID: primitive.NewObjectID(),
	}

	_, err := managerToken.CreateAccessToken(ctx, user)

	assert.ErrorContains(t, err, "user email is required")
}

func TestCreateAccessTokenSuccess(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	user := &models.User{
		ID:    primitive.NewObjectID(),
		Email: "user1@gmail.com",
	}

	token, _ := managerToken.CreateAccessToken(ctx, user)

	assert.NotEmpty(t, token)
}

func TestCreateRefreshTokenIDReturnsError(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	ID := primitive.NilObjectID

	_, err := managerToken.CreateRefreshToken(ctx, ID)

	assert.ErrorContains(t, err, "user id is required")
}

func TestCreateRefreshTokenSuccess(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	ID := primitive.NewObjectID()

	refreshToken, _ := managerToken.CreateRefreshToken(ctx, ID)

	assert.NotEmpty(t, refreshToken)
}

// func TestSetAccessTokenToCookieSuccess(t *testing.T) {
// 	w := httptest.NewRecorder()
// 	ctx, _ := gin.CreateTestContext(w)

// 	user := &models.User{
// 		ID:    primitive.NewObjectID(),
// 		Email: "user1@gmail.com",
// 	}

// 	token, _ := managerToken.CreateAccessToken(ctx, user)
// 	managerToken.SetAccessTokenToHead(ctx, token)

// 	tokenString := getAccessToken(ctx)

// 	assert.EqualValues(t, token, tokenString)
// }

// func TestRemoveCookieAccessTokenSuccess(t *testing.T) {
// 	w := httptest.NewRecorder()
// 	ctx, _ := gin.CreateTestContext(w)

// 	user := &models.User{
// 		ID:    primitive.NewObjectID(),
// 		Email: "user1@gmail.com",
// 	}

// 	token, _ := managerToken.CreateAccessToken(ctx, user)
// 	managerToken.SetAccessTokenToHead(ctx, token)
// 	tokenString := getAccessToken(ctx)

// 	managerToken.RemoveHeadAccessToken(ctx)
// 	tokenRemoved := getAccessToken(ctx)

// 	assert.EqualValues(t, token, tokenString)
// 	assert.Empty(t, tokenRemoved)
// }

// func getAccessToken(ctx *gin.Context) string {
// 	h := ctx.Writer.Header()
// 	cookies := h["Set-Cookie"]

// 	cookie := cookies[len(cookies)-1]

// 	parts := strings.Split(textproto.TrimString(cookie), ";")

// 	return strings.Split(parts[0], "=")[1]
// }
