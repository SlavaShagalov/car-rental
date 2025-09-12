package errors

import (
	"errors"
)

var (
	// Common repository
	ErrDb = errors.New("database error")

	// Users
	ErrUserNotFound      = errors.New("user not found")
	ErrUserAlreadyExists = errors.New("user already exists")

	// Auth
	ErrWrongLoginOrPassword = errors.New("wrong login or password")
	ErrGetHashedPassword    = errors.New("get hashed password error")
	ErrSessionNotFound      = errors.New("session not found")

	// HTTP
	ErrReadBody         = errors.New("read request body error")
	ErrBadSessionCookie = errors.New("bad session cookie")
)
