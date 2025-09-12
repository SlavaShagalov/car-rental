package bcrypt

import (
	"context"

	"golang.org/x/crypto/bcrypt"

	pkgHasher "github.com/SlavaShagalov/car-rental/internal/pkg/hasher"
)

type hasher struct{}

func New() pkgHasher.Hasher {
	return &hasher{}
}

func (h *hasher) GetHashedPassword(ctx context.Context, password string) (string, error) {
	pswd, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(pswd), err
}

func (h *hasher) CompareHashAndPassword(ctx context.Context, hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}
