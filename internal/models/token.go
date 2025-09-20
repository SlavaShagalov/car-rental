package models

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

type AuthorizeRequest struct {
	ResponseType string `query:"response_type" validate:"required"`
	ClientID     string `query:"client_id" validate:"required"`
	RedirectURI  string `query:"redirect_uri" validate:"required"`
	Scope        string `query:"scope" validate:"required"`
}

type TokenRequest struct {
	GrantType    string `form:"grant_type" validate:"required"`
	Code         string `form:"code"`
	RedirectURI  string `form:"redirect_uri" validate:"required"`
	ClientID     string `form:"client_id" validate:"required"`
	ClientSecret string `form:"client_secret" validate:"required"`
	Username     string `form:"username"`
	Password     string `form:"password"`
}
