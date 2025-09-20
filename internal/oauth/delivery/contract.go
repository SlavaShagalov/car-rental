package delivery

import (
	"context"

	"github.com/SlavaShagalov/car-rental/internal/models"
	"github.com/SlavaShagalov/car-rental/internal/oauth/usecase"
	"github.com/SlavaShagalov/car-rental/internal/pkg/app"
)

type UseCase interface {
	app.HealthChecker

	SignIn(ctx context.Context, params usecase.SignInParams) (models.User, string, error)
	SignUp(ctx context.Context, params usecase.SignUpParams) (models.User, string, error)
	GetByID(ctx context.Context, id int) (models.User, error)
}
