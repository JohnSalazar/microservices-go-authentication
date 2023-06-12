package mocks

import (
	"errors"

	common_services "github.com/JohnSalazar/microservices-go-common/services"
)

type EmailServiceMock struct {
	emailService common_services.EmailService
}

var emailServiceInterface common_services.EmailService

var Code string

func NewEmailServiceMock() *EmailServiceMock {
	return &EmailServiceMock{
		emailService: emailServiceInterface,
	}
}

func (s *EmailServiceMock) SendPasswordCode(email string, code string) error {
	if email == "" {
		return errors.New("invalid email address")
	}

	if code == "" {
		return errors.New("invalid code")
	}

	Code = code

	return nil
}

func (s *EmailServiceMock) SendSupportMessage(message string) error {
	if message == "" {
		return errors.New("invalid message")
	}

	return nil
}

func (s *EmailServiceMock) GetCode() string {
	return Code
}
