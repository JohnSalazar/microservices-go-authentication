package mocks

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type EmailCode struct {
	ID        primitive.ObjectID `json:"_id"`
	Email     string             `json:"email"`
	Code      string             `json:"code"`
	ExpiresAt time.Time          `json:"expires_at"`
}

var emailCodes []*EmailCode

type RequestCodeRepositoryMock struct{}

func NewRequestCodeRepositoryMock() *RequestCodeRepositoryMock {
	return &RequestCodeRepositoryMock{}
}

func (r *RequestCodeRepositoryMock) ClearCollection() {
	emailCodes = []*EmailCode{}
}

func (r *RequestCodeRepositoryMock) find(email string, code string) *EmailCode {
	for _, emailCode := range emailCodes {
		if emailCode.Email == email && emailCode.Code == code {
			return emailCode
		}
	}

	return nil
}

func (r *RequestCodeRepositoryMock) CodeExists(ctx context.Context, email string, code string) bool {
	emailCode := r.find(email, code)

	return emailCode != nil
}

func (r *RequestCodeRepositoryMock) CreateCode(ctx context.Context, email string, code string) error {
	if !r.CodeExists(ctx, email, code) {
		emailCodes = append(emailCodes, &EmailCode{primitive.NewObjectID(), email, code, time.Now().UTC().Add(5 * time.Minute)})
	}

	return nil
}

func (r *RequestCodeRepositoryMock) ValidatePasswordUpdateCode(ctx context.Context, email string, code string) bool {
	emailCode := r.find(email, code)
	if emailCode.ExpiresAt.After(time.Now().UTC()) {
		emailCode.ExpiresAt = time.Now().UTC()

		for i, element := range emailCodes {
			if element.Email == email && element.Code == code {
				emailCodes[i] = emailCode
				return true
			}
		}
	}

	return false
}
