package delivery

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"github.com/SlavaShagalov/car-rental/internal/models"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"log/slog"
	"strings"
	"time"

	"github.com/SlavaShagalov/car-rental/internal/oauth/delivery/errors"
	"github.com/SlavaShagalov/car-rental/internal/oauth/usecase"
)

// Authorization code хранилище
type AuthCode struct {
	Code        string
	ClientID    string
	RedirectURI string
	UserID      int
	Scope       string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

var (
	authCodes = make(map[string]*AuthCode)
)

// Сессия авторизации
type AuthSession struct {
	ID          string
	ClientID    string
	RedirectURI string
	Scope       string
	CreatedAt   time.Time
	UserID      int
}

type Delivery struct {
	useCase      UseCase
	privateKey   *rsa.PrivateKey
	publicKey    *rsa.PublicKey
	jwkID        string
	logger       *slog.Logger
	clientID     string
	clientSecret string
	redirectURI  string
	authSessions map[string]*AuthSession
}

// setupRSAKeys генерирует новую пару RSA ключей
func setupRSAKeys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	// Генерируем приватный ключ размером 2048 бит
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Проверяем корректность ключа
	if err := privateKey.Validate(); err != nil {
		return nil, nil, fmt.Errorf("failed to validate RSA key: %w", err)
	}

	// Публичный ключ извлекается из приватного
	publicKey := &privateKey.PublicKey

	return privateKey, publicKey, nil
}

func New(
	useCase UseCase,
	logger *slog.Logger,
) *Delivery {
	privateKey, publicKey, err := setupRSAKeys()
	if err != nil {
		return nil
	}

	return &Delivery{
		useCase:      useCase,
		privateKey:   privateKey,
		publicKey:    publicKey,
		jwkID:        "jwk-id",
		logger:       logger,
		clientID:     "car-rental-client-id",
		clientSecret: "car-rental-client-secret",
		redirectURI:  "http://localhost:8010/api/v1/auth/callback",
		authSessions: make(map[string]*AuthSession),
	}
}

func (d *Delivery) HealthCheck(ctx context.Context) error {
	return d.useCase.HealthCheck(ctx)
}

func (d *Delivery) AddHandlers(router fiber.Router) {
	router.Post("/signup", d.signup)
	router.Post("/signin", d.signin)
	router.Delete("/logout", d.logout)
	router.Get("/me", d.me)

	// other
	router.Get("/authorize", d.Authorize)
	router.Post("/register", d.signup)

	router.Get("/login", d.handleLoginPage)
	router.Post("/login", d.handleLogin)

	router.Get("/consent", d.handleConsentPage)
	router.Post("/consent", d.handleConsent)

	router.Post("/token", d.handleToken)

	router.Get("/callback", d.handleCallback)

	router.Get("/.well-known/jwks.json", d.jwks)
}

// Token endpoint (базовая реализация)
func (d *Delivery) handleToken(c *fiber.Ctx) error {
	// Реализация обмена code на token
	// Это упрощенная версия для демонстрации
	grantType := c.FormValue("grant_type")
	code := c.FormValue("code")
	redirectURI := c.FormValue("redirect_uri")
	clientID := c.FormValue("client_id")
	//clientSecret := c.FormValue("client_secret")
	_ = c.FormValue("client_secret")

	if grantType != "authorization_code" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":             "unsupported_grant_type",
			"error_description": "Поддерживается только grant_type=authorization_code",
		})
	}

	// Проверяем authorization code
	authCode, exists := authCodes[code]
	if !exists || time.Now().After(authCode.ExpiresAt) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":             "invalid_grant",
			"error_description": "Неверный или устаревший код авторизации",
		})
	}

	// Проверяем client credentials
	if clientID != authCode.ClientID {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":             "invalid_client",
			"error_description": "Неверные учетные данные клиента",
		})
	}

	// Проверяем redirect_uri
	if redirectURI != authCode.RedirectURI {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":             "invalid_request",
			"error_description": "Неверный redirect_uri",
		})
	}

	// Генерируем id token
	user, err := d.useCase.GetByID(c.Context(), authCode.UserID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":             "server_error",
			"error_description": "Пользователь не найден",
		})
	}

	idToken, err := d.generateIDToken(user, authCode.ClientID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":             "server_error" + err.Error(),
			"error_description": "Ошибка генерации ID токена",
		})
	}

	// Удаляем использованный код
	delete(authCodes, code)

	// Возвращаем токен
	return c.JSON(fiber.Map{
		"token_type": "Bearer",
		"expires_in": 86400,
		"id_token":   idToken,
		"scope":      authCode.Scope,
	})
}

// Обработчик callback
func (d *Delivery) handleCallback(c *fiber.Ctx) error {
	var req CallbackRequest
	if err := c.QueryParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(CallbackResponse{
			Error:            "invalid_request",
			ErrorDescription: "Неверный формат запроса",
		})
	}

	// Проверяем обязательные параметры
	if req.Code == "" {
		return c.Status(fiber.StatusBadRequest).JSON(CallbackResponse{
			Error:            "invalid_request",
			ErrorDescription: "Отсутствует код авторизации",
		})
	}

	// Ищем authorization code
	authCode, exists := authCodes[req.Code]
	if !exists {
		return c.Status(fiber.StatusBadRequest).JSON(CallbackResponse{
			Error:            "invalid_grant",
			ErrorDescription: "Неверный или устаревший код авторизации",
		})
	}

	// Проверяем срок действия кода
	if time.Now().After(authCode.ExpiresAt) {
		delete(authCodes, req.Code) // Удаляем просроченный код
		return c.Status(fiber.StatusBadRequest).JSON(CallbackResponse{
			Error:            "invalid_grant",
			ErrorDescription: "Код авторизации истек",
		})
	}

	// =====
	// Генерируем id token
	user, err := d.useCase.GetByID(c.Context(), authCode.UserID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":             "server_error",
			"error_description": "Пользователь не найден",
		})
	}

	idToken, err := d.generateIDToken(user, authCode.ClientID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":             "server_error" + err.Error(),
			"error_description": "Ошибка генерации ID токена",
		})
	}

	// Удаляем использованный код
	delete(authCodes, req.Code)

	// Возвращаем токен
	return c.JSON(fiber.Map{
		"token_type": "Bearer",
		"expires_in": 3600,
		"id_token":   idToken,
		"scope":      authCode.Scope,
	})
	// =====
}

// Вспомогательная функция для получения описания ошибки
func getErrorDescription(errorCode string) string {
	switch errorCode {
	case "access_denied":
		return "Пользователь отказал в доступе"
	case "invalid_request":
		return "Неверный запрос"
	case "unauthorized_client":
		return "Клиент не авторизован"
	case "unsupported_response_type":
		return "Неподдерживаемый тип ответа"
	case "invalid_scope":
		return "Неверная область видимости"
	case "server_error":
		return "Ошибка сервера"
	case "temporarily_unavailable":
		return "Временно недоступно"
	default:
		return "Неизвестная ошибка"
	}
}

func (d *Delivery) Authorize(c *fiber.Ctx) error {
	var req models.AuthorizeRequest
	if err := c.QueryParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":             "invalid_request",
			"error_description": "Неверный формат запроса",
		})
	}

	// Валидация обязательных параметров
	if req.ResponseType != "code" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":             "unsupported_response_type",
			"error_description": "Поддерживается только response_type=code",
		})
	}

	if req.ClientID != d.clientID {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":             "invalid_client",
			"error_description": "Неизвестный клиент",
		})
	}

	//// Проверка redirect_uri
	//if req.RedirectURI != "" {
	//	validRedirect := false
	//	if d.redirectURI == req.RedirectURI {
	//		validRedirect = true
	//	}
	//
	//	if !validRedirect {
	//		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
	//			"error":             "invalid_request",
	//			"error_description": "Неверный redirect_uri",
	//		})
	//	}
	//} else {
	//	req.RedirectURI = d.redirectURI
	//}

	// Проверка scope
	scopes := strings.Split(req.Scope, " ")
	validScopes := []string{"openid", "profile", "email"}
	for _, scope := range scopes {
		valid := false
		for _, validScope := range validScopes {
			if scope == validScope {
				valid = true
				break
			}
		}

		if !valid {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":             "invalid_scope",
				"error_description": fmt.Sprintf("Неверный scope: %s", scope),
			})
		}
	}

	// Создаем сессию авторизации
	sessionID, err := generateRandomString(32)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":             "server_error",
			"error_description": "Ошибка сервера",
		})
	}

	authSession := &AuthSession{
		ID:          sessionID,
		ClientID:    req.ClientID,
		RedirectURI: req.RedirectURI,
		Scope:       req.Scope,
		CreatedAt:   time.Now(),
	}

	d.authSessions[sessionID] = authSession

	// Перенаправляем на страницу логина
	return c.Redirect(fmt.Sprintf("/api/v1/auth/login?session_id=%s", sessionID))
}

// Пользователь
type User struct {
	ID       string
	Username string
	Email    string
	Role     string
}

// Обработчик логина
func (d *Delivery) handleLogin(c *fiber.Ctx) error {
	sessionID := c.FormValue("session_id")
	username := c.FormValue("username")
	password := c.FormValue("password")

	if sessionID == "" || username == "" || password == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Не все поля заполнены")
	}

	// Находим сессию
	session, exists := d.authSessions[sessionID]
	if !exists {
		return c.Status(fiber.StatusBadRequest).SendString("Неверная сессия")
	}

	params := usecase.SignInParams{
		Username: username,
		Password: password,
	}

	user, _, err := d.useCase.SignIn(c.Context(), params)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Сохраняем пользователя в сессии
	session.UserID = user.ID

	// TODO
	// Генерируем authorization code
	authCode, err := generateRandomString(32)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":             "server_error",
			"error_description": "Ошибка сервера",
		})
	}

	// В реальной системе сохраняли бы код в базу данных
	authCodes[authCode] = &AuthCode{
		Code:        authCode,
		ClientID:    session.ClientID,
		RedirectURI: session.RedirectURI,
		UserID:      session.UserID,
		Scope:       session.Scope,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(3 * time.Hour),
	}

	// Строим URL для redirect
	redirectURL := fmt.Sprintf("%s?code=%s", session.RedirectURI, authCode)

	// Удаляем сессию после использования
	delete(d.authSessions, sessionID)

	return c.Redirect(redirectURL)
}

// Новая функция для отображения страницы согласия
func (d *Delivery) handleConsentPage(c *fiber.Ctx) error {
	sessionID := c.Query("session_id")
	if sessionID == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Не указан session_id")
	}

	// Находим сессию
	session, exists := d.authSessions[sessionID]
	if !exists {
		return c.Status(fiber.StatusBadRequest).SendString("Неверная сессия")
	}

	if session.UserID == 0 {
		return c.Status(fiber.StatusBadRequest).SendString("Пользователь не аутентифицирован")
	}

	user, err := d.useCase.GetByID(c.Context(), session.UserID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).SendString("Пользователь не найден")
	}

	// Парсим scopes
	scopes := strings.Split(session.Scope, " ")
	scopeDescriptions := make(map[string]string)
	for _, scope := range scopes {
		switch scope {
		case "openid":
			scopeDescriptions[scope] = "Доступ к вашей идентификации"
		case "profile":
			scopeDescriptions[scope] = "Доступ к основной информации профиля"
		case "email":
			scopeDescriptions[scope] = "Доступ к вашему email адресу"
		}
	}

	// HTML форма согласия
	html := fmt.Sprintf(`
	<!DOCTYPE html>
	<html>
	<head>
		<title>Согласие - OpenID Provider</title>
		<style>
			body { font-family: Arial, sans-serif; max-width: 500px; margin: 50px auto; padding: 20px; }
			.consent-container { border: 1px solid #ddd; padding: 20px; border-radius: 8px; }
			.user-info { background-color: #f8f9fa; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
			.scopes-list { margin: 20px 0; }
			.scope-item { padding: 10px; border-bottom: 1px solid #eee; }
			.buttons { margin-top: 20px; display: flex; gap: 10px; }
			.btn { padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
			.btn-primary { background-color: #007bff; color: white; }
			.btn-primary:hover { background-color: #0056b3; }
			.btn-secondary { background-color: #6c757d; color: white; }
			.btn-secondary:hover { background-color: #545b62; }
		</style>
	</head>
	<body>
		<div class="consent-container">
			<h2>Запрос разрешений</h2>
			
			<div class="user-info">
				<strong>Вы вошли как:</strong> %s<br>
				<strong>Приложение:</strong> %s
			</div>

			<p>Приложение запрашивает следующие разрешения:</p>
			
			<div class="scopes-list">`, user.Username, session.ClientID)

	for scope, description := range scopeDescriptions {
		html += fmt.Sprintf(`
				<div class="scope-item">
					<strong>%s:</strong> %s
				</div>`, scope, description)
	}

	html += fmt.Sprintf(`
			</div>

			<form method="POST" action="/api/v1/auth/consent">
				<input type="hidden" name="session_id" value="%s">
				<div class="buttons">
					<button type="submit" name="action" value="allow" class="btn btn-primary">Разрешить</button>
					<button type="submit" name="action" value="deny" class="btn btn-secondary">Отклонить</button>
				</div>
			</form>
		</div>
	</body>
	</html>
	`, sessionID)

	c.Set("Content-Type", "text/html; charset=utf-8")
	return c.SendString(html)
}

// Обновленная функция обработки POST запроса согласия
func (d *Delivery) handleConsent(c *fiber.Ctx) error {
	sessionID := c.FormValue("session_id")
	action := c.FormValue("action")

	if sessionID == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Не указан session_id")
	}

	// Находим сессию
	session, exists := d.authSessions[sessionID]
	if !exists {
		return c.Status(fiber.StatusBadRequest).SendString("Неверная сессия")
	}

	if session.UserID == 0 {
		return c.Status(fiber.StatusBadRequest).SendString("Пользователь не аутентифицирован")
	}

	// Если пользователь отказал
	if action == "deny" {
		errorURL := fmt.Sprintf("%s?error=access_denied", session.RedirectURI)
		return c.Redirect(errorURL)
	}

	// Генерируем authorization code
	authCode, err := generateRandomString(32)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":             "server_error",
			"error_description": "Ошибка сервера",
		})
	}

	// В реальной системе сохраняли бы код в базу данных
	authCodes[authCode] = &AuthCode{
		Code:        authCode,
		ClientID:    session.ClientID,
		RedirectURI: session.RedirectURI,
		UserID:      session.UserID,
		Scope:       session.Scope,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(10 * time.Hour),
	}

	// Строим URL для redirect
	redirectURL := fmt.Sprintf("%s?code=%s", session.RedirectURI, authCode)

	// Удаляем сессию после использования
	delete(d.authSessions, sessionID)

	return c.Redirect(redirectURL)
}

// Страница логина
func (d *Delivery) handleLoginPage(c *fiber.Ctx) error {
	sessionID := c.Query("session_id")
	if sessionID == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Не указан session_id")
	}

	// Простая HTML форма для логина
	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>Login - OpenID Provider</title>
		<style>
			body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }
			.form-group { margin-bottom: 15px; }
			label { display: block; margin-bottom: 5px; }
			input[type="text"], input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
			button { background-color: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
			button:hover { background-color: #0056b3; }
		</style>
	</head>
	<body>
		<h2>Вход в систему</h2>
		<form method="POST" action="/api/v1/auth/login">
			<input type="hidden" name="session_id" value="` + sessionID + `">
			<div class="form-group">
				<label for="username">Имя пользователя:</label>
				<input type="text" id="username" name="username" required>
			</div>
			<div class="form-group">
				<label for="password">Пароль:</label>
				<input type="password" id="password" name="password" required>
			</div>
			<button type="submit">Войти</button>
		</form>
	</body>
	</html>
	`

	c.Set("Content-Type", "text/html; charset=utf-8")
	return c.SendString(html)
}

func (d *Delivery) signup(ctx *fiber.Ctx) error {
	var dto SignUpDTO
	err := ctx.BodyParser(&dto)
	if err != nil {
		d.logger.Error(err.Error())
		return ctx.Status(fiber.StatusBadRequest).JSON(errors.ErrInvalidSignUpRequest.Map())
	}

	params := usecase.SignUpParams{
		Name:     dto.Name,
		Username: dto.Username,
		Email:    dto.Email,
		Password: dto.Password,
		Role:     "user",
	}

	user, _, err := d.useCase.SignUp(ctx.Context(), params)
	if err != nil {
		return err
	}

	tokenResponse, err := d.GenerateToken(user)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":             "server_error",
			"error_description": "Failed to generate token",
		})
	}

	return ctx.Status(fiber.StatusCreated).JSON(fiber.Map{
		"user":          user,
		"access_token":  tokenResponse.AccessToken,
		"token_type":    tokenResponse.TokenType,
		"expires_in":    tokenResponse.ExpiresIn,
		"refresh_token": tokenResponse.RefreshToken,
		"id_token":      tokenResponse.IDToken,
	})
}

func (d *Delivery) signin(ctx *fiber.Ctx) error {
	var dto SignUpDTO
	err := ctx.BodyParser(&dto)
	if err != nil {
		d.logger.Error(err.Error())
		return ctx.Status(fiber.StatusBadRequest).JSON(errors.ErrInvalidSignUpRequest.Map())
	}

	params := usecase.SignInParams{
		Username: dto.Username,
		Password: dto.Password,
	}

	user, authToken, err := d.useCase.SignIn(ctx.Context(), params)
	if err != nil {
		return err
	}

	println(authToken)

	return ctx.Status(fiber.StatusOK).JSON(NewSignUpResponseDTO(user))
}

func (d *Delivery) logout(ctx *fiber.Ctx) error {
	return nil
}

func (d *Delivery) me(ctx *fiber.Ctx) error {
	return nil
}

// well-known endpoint
func (d *Delivery) jwks(ctx *fiber.Ctx) error {
	jwks := d.GetJWKS()

	return ctx.Status(fiber.StatusOK).JSON(jwks)
}

func (d *Delivery) GenerateToken(user models.User) (*models.TokenResponse, error) {
	// Create ID token
	idToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":      user.ID,
		"username": user.Username,
		"email":    user.Email,
		"role":     user.Role,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
		"iat":      time.Now().Unix(),
		"iss":      "rsoi-idp",
		"aud":      "rsoi-client",
	})

	idTokenString, err := idToken.SignedString([]byte("ddd"))
	if err != nil {
		return nil, err
	}

	return &models.TokenResponse{
		TokenType: "Bearer",
		ExpiresIn: 86400,
		IDToken:   idTokenString,
	}, nil
}

func (d *Delivery) GetJWKS() map[string]interface{} {
	// For HMAC, we need to represent the secret as a JWK
	// This is a simplified representation for demonstration
	return map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "oct",
				"kid": d.jwkID,
				"k":   base64.URLEncoding.EncodeToString([]byte("ddd")),
				"alg": "HS256",
				"use": "sig",
			},
		},
	}
}

// Генерация случайной строки
func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}
