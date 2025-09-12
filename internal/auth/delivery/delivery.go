package delivery

import (
	"context"
	"github.com/gofiber/fiber/v2"
	"log/slog"

	"github.com/SlavaShagalov/car-rental/internal/auth/delivery/errors"
	"github.com/SlavaShagalov/car-rental/internal/auth/usecase"
)

type Delivery struct {
	useCase UseCase
	logger  *slog.Logger
}

func New(useCase UseCase, logger *slog.Logger) *Delivery {
	return &Delivery{
		useCase: useCase,
		logger:  logger,
	}
}

func (d *Delivery) HealthCheck(ctx context.Context) error {
	return d.useCase.HealthCheck(ctx)
}

func (d *Delivery) AddHandlers(router fiber.Router) {
	router.Post("/signup", d.signup)
	router.Post("/signin", d.signin)
	router.Delete("/logout", d.logout)
	router.Get("/me", d.me)
}

func (d *Delivery) signup(ctx *fiber.Ctx) error {
	var dto SignUpDTO
	err := ctx.BodyParser(&dto)
	if err != nil {
		d.logger.Error(err.Error())
		return ctx.Status(fiber.StatusBadRequest).JSON(errors.ErrInvalidSignUpRequest.Map())
	}

	params := usecase.SignUpParams{
		Name:     dto.Name,
		Username: dto.Username,
		Email:    dto.Email,
		Password: dto.Password,
	}

	user, token, err := d.useCase.SignUp(ctx.Context(), params)
	if err != nil {
		return err
	}

	println(token)

	return ctx.Status(fiber.StatusOK).JSON(NewSignUpResponseDTO(user))
}

func (d *Delivery) signin(ctx *fiber.Ctx) error {
	var dto SignUpDTO
	err := ctx.BodyParser(&dto)
	if err != nil {
		d.logger.Error(err.Error())
		return ctx.Status(fiber.StatusBadRequest).JSON(errors.ErrInvalidSignUpRequest.Map())
	}

	params := usecase.SignInParams{
		Username: dto.Username,
		Password: dto.Password,
	}

	user, authToken, err := d.useCase.SignIn(ctx.Context(), params)
	if err != nil {
		return err
	}

	println(authToken)

	return ctx.Status(fiber.StatusOK).JSON(NewSignUpResponseDTO(user))
}

func (d *Delivery) logout(ctx *fiber.Ctx) error {
	return nil
}

func (d *Delivery) me(ctx *fiber.Ctx) error {
	return nil
}
