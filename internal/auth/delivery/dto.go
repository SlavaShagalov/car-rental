package delivery

import (
	"github.com/SlavaShagalov/car-rental/internal/models"
	"time"
)

// Структура для callback запроса
type CallbackRequest struct {
	Code  string `query:"code"`
	State string `query:"state"`
	Error string `query:"error"`
}

// Структура для ответа callback
type CallbackResponse struct {
	Code             string `json:"code,omitempty"`
	State            string `json:"state,omitempty"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

type SignUpDTO struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SignUpResponse struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func NewSignUpResponseDTO(user models.User) SignUpResponse {
	return SignUpResponse{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		Name:      user.Name,
		Role:      string(user.Role),
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
}
