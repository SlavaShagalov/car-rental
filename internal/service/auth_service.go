package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/SlavaShagalov/car-rental/internal/models"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrUserExists         = errors.New("user already exists")
	ErrInvalidToken       = errors.New("invalid token")
)

type AuthService interface {
	Login(username, password string) (models.User, error)
	//Register(user *models.CreateUserRequest) (*models.User, error)
	//GenerateToken(user models.User) (*models.TokenResponse, error)
	ValidateToken(tokenString string) (*jwt.Token, error)
	//GetUserFromToken(token *jwt.Token) (*models.UserInfo, error)
	GenerateAuthCode(userID, clientID string) (string, error)
	ValidateAuthCode(code, clientID string) (string, error)
}

type authService struct {
	userRepo  Repository
	jwtSecret string
	jwkID     string
	authCodes map[string]authCodeInfo
}

type authCodeInfo struct {
	userID    string
	clientID  string
	expiresAt time.Time
}

func NewAuthService(userRepo Repository, jwtSecret, jwkID string) AuthService {
	return &authService{
		userRepo:  userRepo,
		jwtSecret: jwtSecret,
		jwkID:     jwkID,
		authCodes: make(map[string]authCodeInfo),
	}
}

func (s *authService) Login(username, password string) (models.User, error) {
	user, err := s.userRepo.GetByUsername(context.Background(), username)
	if err != nil {
		return models.User{}, ErrInvalidCredentials
	}

	if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return models.User{}, ErrInvalidCredentials
	}

	return user, nil
}

// ValidateToken Валидация токена, пришедшего от клиента.
func (s *authService) ValidateToken(tokenString string) (*jwt.Token, error) {
	// 1. Парсим токен в структуру *jwt.Token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.jwtSecret), nil
	})

	if err != nil {
		return nil, ErrInvalidToken
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	return token, nil
}

//func (s *authService) GetUserFromToken(token *jwt.Token) (*models.UserInfo, error) {
//	claims, ok := token.Claims.(jwt.MapClaims)
//	if !ok {
//		return nil, ErrInvalidToken
//	}
//
//	return &models.UserInfo{
//		Sub:      claims["sub"].(string),
//		Username: claims["username"].(string),
//		Email:    claims["email"].(string),
//		Role:     models.Role(claims["role"].(string)),
//	}, nil
//}

func (s *authService) GenerateAuthCode(userID, clientID string) (string, error) {
	code := generateRandomString(32)
	s.authCodes[code] = authCodeInfo{
		userID:    userID,
		clientID:  clientID,
		expiresAt: time.Now().Add(5 * time.Minute),
	}
	return code, nil
}

func (s *authService) ValidateAuthCode(code, clientID string) (string, error) {
	info, exists := s.authCodes[code]
	if !exists {
		return "", errors.New("invalid auth code")
	}

	if time.Now().After(info.expiresAt) {
		delete(s.authCodes, code)
		return "", errors.New("auth code expired")
	}

	if info.clientID != clientID {
		return "", errors.New("client ID mismatch")
	}

	delete(s.authCodes, code)
	return info.userID, nil
}

func generateID() string {
	return generateRandomString(16)
}

func generateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
