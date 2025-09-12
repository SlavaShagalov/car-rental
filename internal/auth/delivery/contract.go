package delivery

import (
	"context"

	"github.com/SlavaShagalov/car-rental/internal/auth/usecase"
	"github.com/SlavaShagalov/car-rental/internal/models"
	"github.com/SlavaShagalov/car-rental/internal/pkg/app"
)

type UseCase interface {
	app.HealthChecker

	SignIn(ctx context.Context, params usecase.SignInParams) (models.User, string, error)
	SignUp(ctx context.Context, params usecase.SignUpParams) (models.User, string, error)
}
