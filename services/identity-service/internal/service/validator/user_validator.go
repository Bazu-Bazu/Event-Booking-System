package validator

import (
	"net/mail"
	"strings"
	"unicode/utf8"

	"github.com/Bazu-Bazu/Event-Booking-System/identity-service/internal/apperror"
)

const (
	minPasswordLength = 8
	maxPasswordLength = 72

	minNicknameLength = 3
	maxNicknameLength = 32
)

func ValidateEmail(email string) (string, error) {
	email = strings.TrimSpace(email)

	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email {
		return "", apperror.ErrInvalidEmail
	}

	return email, nil
}

func ValidateNickname(nickname string) (string, error) {
	nickname = strings.TrimSpace(nickname)

	length := utf8.RuneCountInString(nickname)
	if length < minNicknameLength || length > maxNicknameLength {
		return "", apperror.ErrInvalidNickname
	}

	return nickname, nil
}

func ValidatePassword(password string) error {
	length := utf8.RuneCountInString(password)
	if length < minPasswordLength || len(password) > maxPasswordLength {
		return apperror.ErrInvalidPassword
	}

	return nil
}
