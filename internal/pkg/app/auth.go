package app

import (
	"context"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
	"log/slog"
	"net/http"
)

type ctxKey string

const (
	bearerKey   ctxKey = "bearer"
	usernameKey ctxKey = "username"
)

//// NewAuth create auth middleware
//func NewAuth(jwksURL string, logger *slog.Logger) (fiber.Handler, error) {
//	jwks, err := keyfunc.Get(jwksURL, keyfunc.Options{})
//	if err != nil {
//		return nil, errors.Wrap(err, "load JWKs")
//	}
//
//	return func(ctx *fiber.Ctx) error {
//		// Проверяем наличие заголовка "Authorization: Bearer ..."
//		header := ctx.Get("Authorization")
//		if header == "" || !strings.HasPrefix(header, "Bearer ") {
//			return ctx.SendStatus(fiber.StatusUnauthorized)
//		}
//
//		token := strings.TrimPrefix(header, "Bearer ")
//
//		// Парсим JWT токен
//		username, err := extractUsername(token, jwks.Keyfunc)
//		if err != nil {
//			logger.Error(err.Error())
//			return ctx.SendStatus(fiber.StatusUnauthorized)
//		}
//
//		reqCtx := ctx.UserContext()
//		reqCtx = context.WithValue(reqCtx, bearerKey, token)
//		reqCtx = context.WithValue(reqCtx, usernameKey, username)
//		ctx.SetUserContext(reqCtx)
//
//		return ctx.Next()
//	}, nil
//}

// NewAuth create auth middleware
func NewAuth(jwksURL string, logger *slog.Logger) (fiber.Handler, error) {
	return func(ctx *fiber.Ctx) error {
		return ctx.Next()
	}, nil
}

func AddAuth(ctx context.Context, req *http.Request) error {
	ctxToken := ctx.Value(bearerKey)
	if ctxToken == nil {
		return errors.New("missing bearer token")
	}

	token, ok := ctxToken.(string)
	if !ok {
		return fmt.Errorf("invalid type of bearer token %v", ctxToken)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	return nil
}

func extractUsername(token string, keyFunc jwt.Keyfunc) (string, error) {
	parsedToken, err := jwt.Parse(token, keyFunc)
	if err != nil {
		return "", errors.Wrap(err, "parse jwt")
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid type of token claims")
	}

	username, ok := claims["preferred_username"].(string)
	if !ok {
		return "", errors.New("missing 'preferred_username' in claims")
	}

	return username, nil
}
