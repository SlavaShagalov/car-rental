package delivery

import (
	"fmt"
	"github.com/SlavaShagalov/car-rental/internal/models"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

// Конфигурация OpenID Provider
type OIDCConfig struct {
	Issuer        string
	ClientID      string
	ClientSecret  string
	RedirectURIs  []string
	JWKSURI       string
	AuthEndpoint  string
	TokenEndpoint string
}

var (
	oidcConfig = &OIDCConfig{
		Issuer:        "http://localhost:3000",
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		RedirectURIs:  []string{"http://localhost:3001/callback"},
		JWKSURI:       "http://localhost:3000/.well-known/jwks.json",
		AuthEndpoint:  "http://localhost:3000/authorize",
		TokenEndpoint: "http://localhost:3000/token",
	}
)

// Генерация ID token
func (d *Delivery) generateIDToken(user models.User, clientID string) (string, error) {
	claims := jwt.MapClaims{
		"sub":       user.ID,
		"iss":       oidcConfig.Issuer,
		"aud":       clientID,
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"auth_time": time.Now().Unix(),
		"name":      user.Username,
		"email":     user.Email,
		"role":      user.Role,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Подписываем токен RSA приватным ключом
	signedToken, err := token.SignedString(d.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, nil
}

// VerifyToken проверяет валидность JWT токена с RSA публичным ключом
func (d *Delivery) VerifyToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Проверяем алгоритм подписи
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return d.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return token, nil
}
