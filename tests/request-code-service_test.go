package tests

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCreateCodeSuccess(t *testing.T) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	email := "user1@gmail.com"

	err := requestCodeService.CreateCode(ctx, email)

	assert.NoError(t, err)
}

func TestCreateCodeError(t *testing.T) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	email := ""

	err := requestCodeService.CreateCode(ctx, email)

	assert.Error(t, err)
}
