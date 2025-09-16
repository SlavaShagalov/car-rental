package repository

import (
	"context"
	"database/sql"
	"log/slog"

	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"

	"github.com/SlavaShagalov/car-rental/internal/auth/usecase"
	"github.com/SlavaShagalov/car-rental/internal/models"
	pkgErrors "github.com/SlavaShagalov/car-rental/internal/pkg/errors"
)

type SqlxRepository struct {
	db     *sqlx.DB
	logger *slog.Logger
}

func NewSqlxRepository(db *sqlx.DB, logger *slog.Logger) *SqlxRepository {
	return &SqlxRepository{
		db:     db,
		logger: logger,
	}
}

func (r *SqlxRepository) HealthCheck(ctx context.Context) error {
	return r.db.PingContext(ctx)
}

func (r *SqlxRepository) Create(_ context.Context, params usecase.CreateParams) (models.User, error) {
	const createCmd = `
	INSERT INTO users (name, username, email, hashed_password, role)
	VALUES ($1, $2, $3, $4, $5)
	RETURNING id, username, hashed_password, email, name, role, created_at, updated_at;`

	row := r.db.QueryRow(createCmd, params.Name, params.Username, params.Email, params.HashedPassword, params.Role)

	var user models.User
	err := scanUser(row, &user)
	if err != nil {
		r.logger.Error(err.Error())

		return models.User{}, errors.Wrap(err, "failed to create user")
	}

	return user, nil
}

func (r *SqlxRepository) GetByUsername(ctx context.Context, username string) (models.User, error) {
	const getByUsernameCmd = `
	SELECT id, username, hashed_password, email, name, role, created_at, updated_at
	FROM users
	WHERE username = $1;`

	row := r.db.QueryRow(getByUsernameCmd, username)

	var user models.User
	err := scanUser(row, &user)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, pkgErrors.ErrUserNotFound
		}

		r.logger.Error("GetByUsername: " + err.Error())

		return models.User{}, pkgErrors.ErrDb
	}

	return user, nil
}

func (r *SqlxRepository) GetByID(ctx context.Context, id int) (models.User, error) {
	const getByUsernameCmd = `
	SELECT id, username, hashed_password, email, name, role, created_at, updated_at
	FROM users
	WHERE id = $1;`

	row := r.db.QueryRow(getByUsernameCmd, id)

	var user models.User
	err := scanUser(row, &user)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, pkgErrors.ErrUserNotFound
		}

		r.logger.Error("GetByID: " + err.Error())

		return models.User{}, pkgErrors.ErrDb
	}

	return user, nil
}

func scanUser(row *sql.Row, user *models.User) error {
	err := row.Scan(
		&user.ID,
		&user.Username,
		&user.Password,
		&user.Email,
		&user.Name,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return err
	}

	return nil
}
