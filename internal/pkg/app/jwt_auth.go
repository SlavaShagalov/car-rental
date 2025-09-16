package app

import (
	"github.com/SlavaShagalov/car-rental/internal/service"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

func JWTAuthMiddleware(authService service.AuthService) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// В open id provider должен приходить Authorization заголовок
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":             "unauthorized",
				"error_description": "Authorization header required",
			})
		}

		// Extract token from "Bearer <token>"
		if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":             "unauthorized",
				"error_description": "Invalid authorization format",
			})
		}

		tokenString := authHeader[7:]
		token, err := authService.ValidateToken(tokenString)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":             "invalid_token",
				"error_description": "Invalid or expired token",
			})
		}

		// Store token in context for later use
		c.Locals("user", token)

		return c.Next()
	}
}

func AdminOnlyMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := c.Locals("user").(*jwt.Token)
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":             "invalid_token",
				"error_description": "Invalid token claims",
			})
		}

		role, ok := claims["role"].(string)
		if !ok || role != "admin" {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":             "insufficient_permissions",
				"error_description": "Admin role required",
			})
		}

		return c.Next()
	}
}
