package http

import (
	"authentication/src/dtos"
	"authentication/src/models"

	"github.com/gin-gonic/gin"

	common_models "github.com/JohnSalazar/microservices-go-common/models"
)

type ResponseCredentials struct {
	AccessToken  string                `json:"accessToken"`
	RefreshToken string                `json:"refreshToken"`
	User         *dtos.UserCredentials `json:"user"`
}

func NewResponseCredentials(c *gin.Context, statusCode int, user *models.User, accessToken string, refreshToken string) {
	response := &ResponseCredentials{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User: &dtos.UserCredentials{
			Id:      user.ID,
			Email:   user.Email,
			Claims:  []common_models.Claims(user.Claims),
			Version: user.Version,
		},
	}

	c.JSON(statusCode, response)
}
