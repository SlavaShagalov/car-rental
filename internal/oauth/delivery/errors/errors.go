package errors

type AuthError string

func (e AuthError) Error() string {
	return string(e)
}

func (e AuthError) Map() map[string]any {
	return map[string]any{"message": e.Error()}
}

const (
	ErrInvalidSignUpRequest AuthError = "invalid sign up request"
)
