package hasher

import "context"

type Hasher interface {
	GetHashedPassword(ctx context.Context, password string) (string, error)
	CompareHashAndPassword(ctx context.Context, hashedPassword, password string) error
}
