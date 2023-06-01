package dtos

type UpdateEmail struct {
	ID      string `json:"id"`
	Email   string `json:"email"`
	Version uint   `json:"version"`
}
