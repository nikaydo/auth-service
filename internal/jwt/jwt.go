package jwt

import (
	"errors"
	"fmt"
	"main/internal/config"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
)

var (
	ErrTokenExpired = errors.New("token is expired")
)

type JwtTokens struct {
	AccessToken  string
	RefreshToken string
	Env          config.Env
}

func (j *JwtTokens) CreateTokens(id int, username, role string) error {
	var err error
	j.AccessToken, err = j.CreateToken(id, username, role, j.Env.EnvMap["SECRET_TTL"], j.Env.EnvMap["SECRET"])
	if err != nil {
		return fmt.Errorf("error creating JWT token: %w", err)
	}
	j.RefreshToken, err = j.CreateToken(id, username, role, j.Env.EnvMap["REFRESH_TTL"], j.Env.EnvMap["SECRET_REFRESH"])
	if err != nil {
		return fmt.Errorf("error creating refresh token: %w", err)
	}
	return nil
}

func (j *JwtTokens) CreateToken(id int, username, role, tokenTTL, secret string) (string, error) {
	exTime, err := strconv.Atoi(tokenTTL)
	if err != nil {
		return "", fmt.Errorf("failed to parse TTL from environment: %w", err)
	}
	tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"sub":      id,
			"username": username,
			"iss":      "server",
			"role":     role,
			"aud":      "video",
			"exp":      time.Now().Add(time.Duration(exTime * int(time.Minute))).Unix(),
			"iat":      time.Now().Unix(),
		}).SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("error signing token: %w", err)
	}
	return tokenString, nil
}

func ValidateToken(t, secret string) (int, string, error) {
	token, err := jwt.Parse(t, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("no valid signing method")
		}
		return []byte(secret), nil
	})
	if err != nil {
		if err.Error() == "Token is expired" {
			id, username, err := setClaims(token)
			if err != nil {
				return 0, "", fmt.Errorf("failed to extract claims from expired token: %w", err)
			}
			return id, username, ErrTokenExpired
		}
		return 0, "", fmt.Errorf("failed to parse token: %w", err)
	}
	return setClaims(token)
}

func setClaims(token *jwt.Token) (int, string, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return 0, "", fmt.Errorf("invalid token")
	}
	username, ok := claims["username"].(string)
	if !ok {
		return 0, "", fmt.Errorf("cant parse username from jwt token")
	}
	id, ok := claims["sub"].(float64)
	if !ok {
		return 0, "", fmt.Errorf("cant parse id from jwt token")
	}
	return int(id), username, nil
}
	