package apperror

import "errors"

var (
	ErrEmailTaken          = errors.New("email already taken")
	ErrNicknameTaken       = errors.New("nickanme already taken")
	ErrUserNotFound        = errors.New("user not found")
	ErrNoFieldsToUpdate    = errors.New("no filelds to update")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrInvalidEmail        = errors.New("invalid email")
	ErrInvalidNickname     = errors.New("invalid nickname")
	ErrInvalidPassword     = errors.New("invalid password")
	ErrInvalidCredentials  = errors.New("invalid credentials")
)
