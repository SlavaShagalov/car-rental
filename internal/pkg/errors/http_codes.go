package errors

import "net/http"

var httpCodes = map[error]int{
	// Common repository
	ErrDb: http.StatusInternalServerError,

	// Users
	ErrUserNotFound:      http.StatusNotFound,
	ErrUserAlreadyExists: http.StatusConflict,

	// Auth
	ErrWrongLoginOrPassword: http.StatusBadRequest,
	ErrSessionNotFound:      http.StatusNotFound,

	// HTTP
	ErrReadBody:         http.StatusBadRequest,
	ErrBadSessionCookie: http.StatusBadRequest,
}

func GetHTTPCodeByError(err error) (int, bool) {
	httpCode, exist := httpCodes[err]
	if !exist {
		httpCode = http.StatusInternalServerError
	}
	return httpCode, exist
}
