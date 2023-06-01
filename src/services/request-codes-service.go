package services

import (
	repository "authentication/src/repositories/interfaces"
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"

	common_services "github.com/oceano-dev/microservices-go-common/services"
)

type RequestCodeService struct {
	requestCodeRepository repository.RequestCodeRepository
	emailService          common_services.EmailService
}

func NewRequestCodeService(
	requestCodeRepository repository.RequestCodeRepository,
	emailService common_services.EmailService,
) *RequestCodeService {
	return &RequestCodeService{
		requestCodeRepository: requestCodeRepository,
		emailService:          emailService,
	}
}

func (service *RequestCodeService) codeExists(ctx context.Context, email string) (string, error) {
	createCodeCount := 0
	var code string
	var codeExists bool
	min := 1009
	max := 9978

	for createCodeCount < 5 {
		code = fmt.Sprint(rand.Intn(max-min) + min)
		codeExists = service.requestCodeRepository.CodeExists(ctx, email, code)
		if !codeExists {
			break
		}

		createCodeCount++
	}

	if codeExists {
		return "", fmt.Errorf("failed to generate code")
	}

	return code, nil
}

func (service *RequestCodeService) CreateCode(ctx context.Context, email string) error {
	if email == "" {
		return errors.New("invalid Email")
	}

	code, err := service.codeExists(ctx, email)
	if err != nil {
		return err
	}

	err = service.requestCodeRepository.CreateCode(ctx, email, code)
	if err != nil {
		return err
	}

	go func() {
		err := service.emailService.SendPasswordCode(email, code)
		if err != nil {
			log.Println(err)
		}
	}()

	return nil
}

func (service *RequestCodeService) ValidatePasswordUpdateCode(ctx context.Context, email string, code string) bool {
	if email == "" || code == "" {
		return false
	}

	return service.requestCodeRepository.ValidatePasswordUpdateCode(ctx, email, code)
}
