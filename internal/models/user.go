package models

import "time"

type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

type User struct {
	ID        int
	Username  string
	Password  string
	Email     string
	Name      string
	Role      Role
	CreatedAt time.Time
	UpdatedAt time.Time
}

type CreateUserRequest struct {
	Username string `json:"username" validate:"required,min=3"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=6"`
	Role     Role   `json:"role" validate:"required,oneof=admin user"`
}
