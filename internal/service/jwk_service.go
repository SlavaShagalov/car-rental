package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
)

type JWKService interface {
	GetJWKS() map[string]interface{}
}

type jwkService struct {
	jwtSecret string
	jwkID     string
}

func NewJWKService(jwtSecret, jwkID string) JWKService {
	return &jwkService{
		jwtSecret: jwtSecret,
		jwkID:     jwkID,
	}
}

func (s *jwkService) GetJWKS() map[string]interface{} {
	// For HMAC, we need to represent the secret as a JWK
	// This is a simplified representation for demonstration
	return map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "oct",
				"kid": s.jwkID,
				"k":   base64.URLEncoding.EncodeToString([]byte(s.jwtSecret)),
				"alg": "HS256",
				"use": "sig",
			},
		},
	}
}

// Helper function to generate RSA key (not used in current implementation but good to have)
func generateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func exportRSAPublicKeyAsPEM(pubkey *rsa.PublicKey) (string, error) {
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	pubkeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubkeyBytes,
	})
	return string(pubkeyPEM), nil
}
