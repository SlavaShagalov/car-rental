package handlers

import (
	"github.com/SlavaShagalov/car-rental/internal/service"
	"github.com/docker/docker/libnetwork/config"
)

type WellKnownHandler struct {
	jwkService service.JWKService
	config     *config.Config
}

func NewWellKnownHandler(jwkService service.JWKService, cfg *config.Config) *WellKnownHandler {
	return &WellKnownHandler{
		jwkService: jwkService,
		config:     cfg,
	}
}

//func (h *WellKnownHandler) GetOpenIDConfiguration(c *fiber.Ctx) error {
//	config := map[string]interface{}{
//		"issuer":                                "http://localhost:" + h.config.Port,
//		"authorization_endpoint":                "http://localhost:" + h.config.Port + "/api/v1/authorize",
//		"token_endpoint":                        "http://localhost:" + h.config.Port + "/api/v1/token",
//		"userinfo_endpoint":                     "http://localhost:" + h.config.Port + "/api/v1/userinfo",
//		"jwks_uri":                              "http://localhost:" + h.config.Port + "/.well-known/jwks.json",
//		"response_types_supported":              []string{"code", "token", "id_token"},
//		"subject_types_supported":               []string{"public"},
//		"id_token_signing_alg_values_supported": []string{"HS256"},
//		"scopes_supported":                      []string{"openid", "profile", "email"},
//		"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
//	}
//
//	return c.JSON(config)
//}

//func (h *WellKnownHandler) GetJWKS(c *fiber.Ctx) error {
//	jwks := h.jwkService.GetJWKS()
//	return c.JSON(jwks)
//}
