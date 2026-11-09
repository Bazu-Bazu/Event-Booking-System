package token

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTManager struct {
	secret    []byte
	issuer    string
	accessTTL time.Duration
}

type Claims struct {
	jwt.RegisteredClaims
}

func NewJWTManager(secret string, issuer string, accessTTL time.Duration) (*JWTManager, error) {
	if len(secret) < 32 {
		return nil, errors.New("JWT secret must contain at least 32 bytes")
	}

	if issuer == "" {
		return nil, errors.New("JWT issuer cannot be empty")
	}

	if accessTTL <= 0 {
		return nil, errors.New("access token TTL must be positive")
	}

	return &JWTManager{
		secret:    []byte(secret),
		issuer:    issuer,
		accessTTL: accessTTL,
	}, nil
}

func (m *JWTManager) GenerateAccessToken(userID int64) (string, error) {
	now := time.Now()

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   strconv.FormatInt(userID, 10),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.accessTTL)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString(m.secret)
	if err != nil {
		return "", fmt.Errorf("sign access token: %w", err)
	}

	return signedToken, nil
}

func (m *JWTManager) ParseAccessToken(rawToken string) (int64, error) {
	claims := &Claims{}

	parsedToken, err := jwt.ParseWithClaims(
		rawToken,
		claims,
		func(token *jwt.Token) (any, error) {
			return m.secret, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(m.issuer),
	)
	if err != nil {
		return 0, fmt.Errorf("parse access token: %w", err)
	}

	if !parsedToken.Valid {
		return 0, errors.New("invalid access token")
	}

	userID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil || userID <= 0 {
		return 0, errors.New("invalid user ID in access token")
	}

	return userID, nil
}
