package validators

import (
	"authentication/src/dtos"

	common_models "github.com/JohnSalazar/microservices-go-common/models"
	common_validator "github.com/JohnSalazar/microservices-go-common/validators"
)

type createUser struct {
	Email    string                 `from:"email" json:"email" validate:"required,email"`
	Password string                 `from:"password" json:"password" validate:"required,min=6"`
	Claims   []common_models.Claims `from:"claims" json:"claims" validate:"required,min=1"`
}

type signUp struct {
	Email           string `from:"email" json:"email" validate:"required,email"`
	Password        string `from:"password" json:"password" validate:"required,min=6"`
	PasswordConfirm string `from:"passwordConfirm" json:"passwordConfirm" validate:"omitempty,eqfield=Password"`
}

type signIn struct {
	Email    string `from:"email" json:"email" validate:"required,email"`
	Password string `from:"password" json:"password" validate:"required,min=6"`
}

type updatePassword struct {
	Email                     string `from:"email" json:"email" validate:"required,email"`
	Password                  string `from:"password" json:"password" validate:"required,min=6"`
	PasswordConfirm           string `from:"passwordConfirm" json:"passwordConfirm" validate:"omitempty,eqfield=Password"`
	RequestUpdatePasswordCode string `from:"requestUpdatePasswordCode" json:"requestUpdatePasswordCode" validate:"required,min=4"`
}

type updateEmail struct {
	Email string `from:"email" json:"email" validate:"required,email"`
}

func ValidateCreateUser(fields *dtos.CreateUser) interface{} {
	user := createUser{
		Email:    fields.Email,
		Password: fields.Password,
		Claims:   fields.Claims,
	}

	err := common_validator.Validate(user)
	if err != nil {
		return err
	}

	return nil
}

func ValidateSignUP(fields *dtos.SignUp) interface{} {
	user := signUp{
		Email:           fields.Email,
		Password:        fields.Password,
		PasswordConfirm: fields.PasswordConfirm,
	}

	err := common_validator.Validate(user)
	if err != nil {
		return err
	}

	return nil
}

func ValidateSignIn(fields *dtos.SignIn) interface{} {
	user := signIn{
		Email:    fields.Email,
		Password: fields.Password,
	}

	err := common_validator.Validate(user)
	if err != nil {
		return err
	}

	return nil
}

func ValidateUpdatePassword(fields *dtos.UpdatePassword) interface{} {
	user := updatePassword{
		Email:                     fields.Email,
		Password:                  fields.Password,
		PasswordConfirm:           fields.PasswordConfirm,
		RequestUpdatePasswordCode: fields.RequestUpdatePasswordCode,
	}

	err := common_validator.Validate(user)
	if err != nil {
		return err
	}

	return nil
}

func ValidateUpdateEmail(fields *dtos.UpdateEmail) interface{} {
	user := updateEmail{
		Email: fields.Email,
	}

	err := common_validator.Validate(user)
	if err != nil {
		return err
	}

	return nil
}
