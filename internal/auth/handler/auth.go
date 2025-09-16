package handlers

import (
	"github.com/SlavaShagalov/car-rental/internal/models"
	"github.com/SlavaShagalov/car-rental/internal/service"
	"github.com/docker/docker/libnetwork/config"
	"github.com/gofiber/fiber/v2"
)

type AuthHandler struct {
	authService service.AuthService
	config      *config.Config
}

func NewAuthHandler(authService service.AuthService, cfg *config.Config) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		config:      cfg,
	}
}

func (h *AuthHandler) Token(c *fiber.Ctx) error {
	var req models.TokenRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":             "invalid_request",
			"error_description": "Invalid request",
		})
	}

	// Validate client credentials
	if req.ClientID != h.config.ClientID || req.ClientSecret != h.config.ClientSecret {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":             "invalid_client",
			"error_description": "Invalid client credentials",
		})
	}

	switch req.GrantType {
	case "authorization_code":
		return h.handleAuthorizationCode(c, req)
	case "password":
		return h.handlePasswordGrant(c, req)
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":             "unsupported_grant_type",
			"error_description": "Unsupported grant type",
		})
	}
}

func (h *AuthHandler) handleAuthorizationCode(c *fiber.Ctx, req models.TokenRequest) error {
	if req.Code == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":             "invalid_request",
			"error_description": "Code parameter required",
		})
	}

	userID, err := h.authService.ValidateAuthCode(req.Code, req.ClientID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":             "invalid_grant",
			"error_description": "Invalid authorization code",
		})
	}

	user, err := h.authService.Login(userID, "") // Get user by ID
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":             "server_error",
			"error_description": "Failed to get user",
		})
	}

	tokenResponse, err := h.authService.GenerateToken(user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":             "server_error",
			"error_description": "Failed to generate token",
		})
	}

	return c.JSON(tokenResponse)
}

func (h *AuthHandler) handlePasswordGrant(c *fiber.Ctx, req models.TokenRequest) error {
	if req.Username == "" || req.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":             "invalid_request",
			"error_description": "Username and password required",
		})
	}

	user, err := h.authService.Login(req.Username, req.Password)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":             "invalid_grant",
			"error_description": "Invalid credentials",
		})
	}

	tokenResponse, err := h.authService.GenerateToken(user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":             "server_error",
			"error_description": "Failed to generate token",
		})
	}

	return c.JSON(tokenResponse)
}

func (h *AuthHandler) Callback(c *fiber.Ctx) error {
	// Handle OAuth callback - for simplicity, we'll just return the code
	code := c.Query("code")
	state := c.Query("state")

	if code == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":             "invalid_request",
			"error_description": "Code parameter required",
		})
	}

	// In real implementation, you'd redirect back to client with code and state
	return c.JSON(fiber.Map{
		"code":  code,
		"state": state,
	})
}

//func (h *AuthHandler) UserInfo(c *fiber.Ctx) error {
//	token := c.Locals("user").(*jwt.Token)
//	userInfo, err := h.authService.GetUserFromToken(token)
//	if err != nil {
//		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
//			"error":             "invalid_token",
//			"error_description": "Invalid token",
//		})
//	}
//
//	// Check requested scopes from query parameter
//	scopes := c.Query("scope", "openid")
//
//	response := make(map[string]interface{})
//	response["sub"] = userInfo.Sub
//
//	if containsScope(scopes, "profile") {
//		response["username"] = userInfo.Username
//		response["role"] = userInfo.Role
//	}
//
//	if containsScope(scopes, "email") {
//		response["email"] = userInfo.Email
//	}
//
//	return c.JSON(response)
//}

func containsScope(scopes, target string) bool {
	scopeList := splitScopes(scopes)
	for _, scope := range scopeList {
		if scope == target {
			return true
		}
	}
	return false
}

func splitScopes(scopes string) []string {
	// Simple scope splitting - in real implementation, handle proper OAuth scope parsing
	var result []string
	// Basic split by space
	// You might want to use strings.Fields or more sophisticated parsing
	for i := 0; i < len(scopes); i++ {
		if scopes[i] == ' ' {
			result = append(result, scopes[:i])
			scopes = scopes[i+1:]
			i = 0
		}
	}
	if scopes != "" {
		result = append(result, scopes)
	}
	return result
}
