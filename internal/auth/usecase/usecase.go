package usecase

import (
	"context"
	"log/slog"

	"github.com/pkg/errors"

	"github.com/SlavaShagalov/car-rental/internal/models"
	pkgErrors "github.com/SlavaShagalov/car-rental/internal/pkg/errors"
	pkgHasher "github.com/SlavaShagalov/car-rental/internal/pkg/hasher"
)

type UseCase struct {
	repo   Repository
	logger *slog.Logger
	hasher pkgHasher.Hasher
}

func New(repo Repository, logger *slog.Logger, hasher pkgHasher.Hasher) *UseCase {
	return &UseCase{
		repo:   repo,
		logger: logger,
		hasher: hasher,
	}
}

func (u *UseCase) HealthCheck(ctx context.Context) error {
	return u.repo.HealthCheck(ctx)
}

func (u *UseCase) SignUp(ctx context.Context, params SignUpParams) (models.User, string, error) {
	_, err := u.repo.GetByUsername(ctx, params.Username)
	if !errors.Is(err, pkgErrors.ErrUserNotFound) {
		if err != nil {
			return models.User{}, "", err
		}
		return models.User{}, "", pkgErrors.ErrUserAlreadyExists
	}

	hashedPassword, err := u.hasher.GetHashedPassword(ctx, params.Password)
	if err != nil {
		return models.User{}, "", errors.Wrap(pkgErrors.ErrGetHashedPassword, err.Error())
	}

	repParams := CreateParams{
		Name:           params.Name,
		Username:       params.Username,
		Email:          params.Email,
		Role:           params.Role,
		HashedPassword: hashedPassword,
	}

	user, err := u.repo.Create(ctx, repParams)
	if err != nil {
		return models.User{}, "", err
	}

	// TODO: token
	return user, "token", nil
}

func (u *UseCase) SignIn(ctx context.Context, params SignInParams) (models.User, string, error) {
	user, err := u.repo.GetByUsername(ctx, params.Username)
	if err != nil {
		return models.User{}, "", err
	}

	if err = u.hasher.CompareHashAndPassword(ctx, user.Password, params.Password); err != nil {
		return models.User{}, "", errors.Wrap(pkgErrors.ErrWrongLoginOrPassword, err.Error())
	}

	// TODO: token
	return user, "token", nil
}

func (u *UseCase) GetByID(ctx context.Context, id int) (models.User, error) {
	user, err := u.repo.GetByID(ctx, id)
	if err != nil {
		return models.User{}, err
	}

	// TODO: token
	return user, nil
}
