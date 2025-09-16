package service

import (
	"context"
	"github.com/SlavaShagalov/car-rental/internal/models"
)

type Repository interface {
	HealthCheck(ctx context.Context) error

	//Create(ctx context.Context, params CreateParams) (models.User, error)
	GetByUsername(ctx context.Context, username string) (models.User, error)
}
