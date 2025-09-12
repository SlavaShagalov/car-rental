package models

import "time"

type User struct {
	ID        int
	Username  string
	Password  string
	Email     string
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
}
