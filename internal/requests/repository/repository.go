package repository

import (
	"context"
	"database/sql"
	"errors"
	"github.com/SlavaShagalov/car-rental/pkg/sqlxutils"
	"github.com/jmoiron/sqlx"
	"log/slog"
)

type Request struct {
	Method  string
	URL     string
	Body    string
	Headers string
}

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

func (r *SqlxRepository) GetRequests(ctx context.Context) ([]Request, error) {
	reqs := make([]Request, 0)

	cmd := `select * from requests;`

	err := sqlxutils.Select(ctx, r.db, &reqs, cmd)
	if errors.Is(err, sql.ErrNoRows) {
		return []Request{}, nil
	} else if err != nil {
		return nil, err
	}

	return reqs, nil
}

func (r *SqlxRepository) SaveRequest(ctx context.Context, req Request) (err error) {
	const createCmd = `
	INSERT INTO requests (method, url, body, headers)
	VALUES ($1, $2, $3, $4);`

	_, err = r.db.Exec(createCmd, req.Method, req.URL, req.Body, req.Headers)
	if err != nil {
		return err
	}

	return nil
}
