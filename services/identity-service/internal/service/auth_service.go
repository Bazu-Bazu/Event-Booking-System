package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Bazu-Bazu/Event-Booking-System/identity-service/internal/apperror"
	"github.com/Bazu-Bazu/Event-Booking-System/identity-service/internal/model"
	"github.com/Bazu-Bazu/Event-Booking-System/identity-service/internal/service/input"
	"github.com/Bazu-Bazu/Event-Booking-System/identity-service/internal/service/output"
	"github.com/Bazu-Bazu/Event-Booking-System/identity-service/internal/token"
	"golang.org/x/crypto/bcrypt"
)

type authUserRepository interface {
	GetByEmail(ctx context.Context, email string) (model.User, error)
}

type authRefreshSessionRepository interface {
	CreateWithLimit(ctx context.Context, session model.RefreshSession) error
	Rotate(ctx context.Context, oldTokenHash string, newTokenHash string, newExpiresAt time.Time) (int64, error)
	Revoke(ctx context.Context, tokenHash string) error
}

type AuthService struct {
	userRepo           authUserRepository
	refreshSessionRepo authRefreshSessionRepository
	jwtManager         *token.JWTManager
	refreshTTL         time.Duration
}

func NewAuthService(
	userRepo authUserRepository,
	refreshSessionRepo authRefreshSessionRepository,
	jwtManager *token.JWTManager,
	refreshTTL time.Duration,
) (*AuthService, error) {
	if refreshTTL <= 0 {
		return nil, fmt.Errorf("refresh token TTL must be positive")
	}

	return &AuthService{
		userRepo:           userRepo,
		refreshSessionRepo: refreshSessionRepo,
		jwtManager:         jwtManager,
		refreshTTL:         refreshTTL,
	}, nil
}

func (s *AuthService) Login(ctx context.Context, in input.LoginInput) (output.TokenPair, error) {
	user, err := s.userRepo.GetByEmail(ctx, in.Email)
	if err != nil {
		if errors.Is(err, apperror.ErrUserNotFound) {
			return output.TokenPair{}, apperror.ErrInvalidCredentials
		}

		return output.TokenPair{}, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(in.Password)); err != nil {
		return output.TokenPair{}, apperror.ErrInvalidCredentials
	}

	accessToken, err := s.jwtManager.GenerateAccessToken(user.ID)
	if err != nil {
		return output.TokenPair{}, err
	}

	refreshToken, err := token.GenerateRefreshToken()
	if err != nil {
		return output.TokenPair{}, err
	}

	session := model.RefreshSession{
		UserID:    user.ID,
		TokenHash: token.HashRefreshToken(refreshToken),
		ExpiresAt: time.Now().Add(s.refreshTTL),
	}

	if err := s.refreshSessionRepo.CreateWithLimit(ctx, session); err != nil {
		return output.TokenPair{}, err
	}

	return output.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *AuthService) Refresh(ctx context.Context, in input.RefreshInput) (output.TokenPair, error) {
	if in.RefreshToken == "" {
		return output.TokenPair{}, apperror.ErrInvalidRefreshToken
	}

	oldTokenHash := token.HashRefreshToken(in.RefreshToken)

	newRefreshToken, err := token.GenerateRefreshToken()
	if err != nil {
		return output.TokenPair{}, err
	}

	newExpiresAt := time.Now().Add(s.refreshTTL)

	userID, err := s.refreshSessionRepo.Rotate(
		ctx,
		oldTokenHash,
		token.HashRefreshToken(newRefreshToken),
		newExpiresAt,
	)
	if err != nil {
		return output.TokenPair{}, err
	}

	accessToken, err := s.jwtManager.GenerateAccessToken(userID)
	if err != nil {
		return output.TokenPair{}, err
	}

	return output.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
	}, nil
}

func (s *AuthService) Logout(ctx context.Context, in input.RefreshInput) error {
	if in.RefreshToken == "" {
		return apperror.ErrInvalidRefreshToken
	}

	hash := token.HashRefreshToken(in.RefreshToken)

	return s.refreshSessionRepo.Revoke(ctx, hash)
}
