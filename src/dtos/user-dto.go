package dtos

import (
	"time"

	common_models "github.com/JohnSalazar/microservices-go-common/models"
)

type User struct {
	ID        string                 `json:"id"`
	Email     string                 `json:"email"`
	Claims    []common_models.Claims `json:"claims,omitempty"`
	CreatedAt time.Time              `json:"created_at,omitempty"`
	UpdatedAt time.Time              `json:"updated_at,omitempty"`
	Version   uint                   `json:"version"`
}
