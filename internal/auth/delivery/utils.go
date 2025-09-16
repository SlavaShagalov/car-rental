package delivery

import (
	"github.com/SlavaShagalov/car-rental/internal/models"
	"github.com/golang-jwt/jwt/v5"
	"strings"
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

// Генерация access token
func (d *Delivery) generateAccessToken(user models.User, clientID string, scopes []string) (string, error) {
	claims := jwt.MapClaims{
		"sub":   user.ID,
		"iss":   oidcConfig.Issuer,
		"aud":   clientID,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"scope": strings.Join(scopes, " "),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// В реальной системе используйте настоящий приватный ключ
	return token.SignedString([]byte(d.jwtSecret))
}

// Генерация ID token
func (d *Delivery) generateIDToken(user models.User, clientID, nonce string) (string, error) {
	claims := jwt.MapClaims{
		"sub":                user.ID,
		"iss":                oidcConfig.Issuer,
		"aud":                clientID,
		"exp":                time.Now().Add(time.Hour).Unix(),
		"iat":                time.Now().Unix(),
		"auth_time":          time.Now().Unix(),
		"name":               user.Username,
		"email":              user.Email,
		"email_verified":     true,
		"preferred_username": user.Username,
		"role":               user.Role,
	}

	if nonce != "" {
		claims["nonce"] = nonce
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString([]byte(d.jwtSecret))
}
