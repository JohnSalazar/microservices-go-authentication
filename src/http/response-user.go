package http

import (
	"authentication/src/dtos"
	"authentication/src/models"

	"github.com/gin-gonic/gin"

	common_models "github.com/oceano-dev/microservices-go-common/models"
)

func NewResponseUser(c *gin.Context, statusCode int, user *models.User) {
	response := &dtos.UserCredentials{
		Id:      user.ID,
		Email:   user.Email,
		Claims:  []common_models.Claims(user.Claims),
		Version: user.Version,
	}

	c.JSON(statusCode, response)
}
