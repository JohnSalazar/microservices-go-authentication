package repositories

import (
	"context"
)

type RequestCodeRepository interface {
	CodeExists(ctx context.Context, email string, code string) bool
	CreateCode(ctx context.Context, email string, code string) error
	ValidatePasswordUpdateCode(ctx context.Context, email string, code string) bool
}
