package dtos

type UpdatePassword struct {
	Email                     string `json:"email"`
	Password                  string `json:"password,omitempty"`
	PasswordConfirm           string `json:"passwordConfirm,omitempty"`
	RequestUpdatePasswordCode string `json:"requestUpdatePasswordCode,omitempty"`
}
