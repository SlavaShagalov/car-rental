package usecase

import (
	"context"
	"github.com/SlavaShagalov/car-rental/internal/models"
)

type SignInParams struct {
	Username string
	Password string
}

type SignUpParams struct {
	Name     string
	Username string
	Email    string
	Password string
	Role     string
}

type CreateParams struct {
	Name           string
	Username       string
	Email          string
	HashedPassword string
	Role           string
}

type Repository interface {
	HealthCheck(ctx context.Context) error

	Create(ctx context.Context, params CreateParams) (models.User, error)
	GetByUsername(ctx context.Context, username string) (models.User, error)
	GetByID(ctx context.Context, id int) (models.User, error)
}
