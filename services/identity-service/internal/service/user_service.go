package service

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/Bazu-Bazu/Event-Booking-System/identity-service/internal/apperror"
	"github.com/Bazu-Bazu/Event-Booking-System/identity-service/internal/model"
	"github.com/Bazu-Bazu/Event-Booking-System/identity-service/internal/service/input"
	"github.com/Bazu-Bazu/Event-Booking-System/identity-service/internal/service/output"
	"github.com/Bazu-Bazu/Event-Booking-System/identity-service/internal/service/validator"
	"golang.org/x/crypto/bcrypt"
)

type userRepository interface {
	Save(ctx context.Context, u model.User) (model.User, error)
	GetByID(ctx context.Context, id int64) (model.User, error)
	Delete(ctx context.Context, id int64) error
	Update(ctx context.Context, id int64, update model.UserUpdate) error
	UpdateTx(ctx context.Context, tx *sql.Tx, id int64, update model.UserUpdate) error
}

type refreshSessionRepository interface {
	RevokeAll(ctx context.Context, userID int64) error
	RevokeAllTx(ctx context.Context, tx *sql.Tx, userID int64) error
}

type transactionManager interface {
	WithinTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
}

type UserService struct {
	userRepo           userRepository
	refreshSessionRepo refreshSessionRepository
	txManager          transactionManager
}

func NewUserService(userRepo userRepository, refreshSessionRepo refreshSessionRepository, txManager transactionManager) *UserService {
	return &UserService{
		userRepo:           userRepo,
		refreshSessionRepo: refreshSessionRepo,
		txManager:          txManager,
	}
}

func (s *UserService) CreateUser(ctx context.Context, input input.CreateUserInput) (output.UserOutput, error) {
	email, err := validator.ValidateEmail(input.Email)
	if err != nil {
		return output.UserOutput{}, err
	}

	nickname, err := validator.ValidateNickname(input.Nickname)
	if err != nil {
		return output.UserOutput{}, err
	}

	if err := validator.ValidatePassword(input.Password); err != nil {
		return output.UserOutput{}, err
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return output.UserOutput{}, fmt.Errorf("hash password: %w", err)
	}

	user := model.User{
		Email:        email,
		Nickname:     nickname,
		PasswordHash: string(passwordHash),
	}

	createdUser, err := s.userRepo.Save(ctx, user)
	if err != nil {
		return output.UserOutput{}, err
	}

	return toUserOutput(createdUser), nil
}

func (s *UserService) GetUserByID(ctx context.Context, id int64) (output.UserOutput, error) {
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		return output.UserOutput{}, err
	}

	return toUserOutput(user), nil
}

func (s *UserService) UpdateUser(ctx context.Context, id int64, input input.UserUpdateInput) error {
	if input.Email == nil && input.Nickname == nil && input.Password == nil {
		return apperror.ErrNoFieldsToUpdate
	}

	var update model.UserUpdate

	if input.Email != nil {
		email, err := validator.ValidateEmail(*input.Email)
		if err != nil {
			return err
		}

		update.Email = &email
	}

	if input.Nickname != nil {
		nickname, err := validator.ValidateNickname(*input.Nickname)
		if err != nil {
			return err
		}

		update.Nickname = &nickname
	}

	if input.Password != nil {
		if err := validator.ValidatePassword(*input.Password); err != nil {
			return err
		}

		passwordHash, err := bcrypt.GenerateFromPassword([]byte(*input.Password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("hash password: %w", err)
		}

		hash := string(passwordHash)
		update.PasswordHash = &hash
	}

	if input.Password == nil {
		return s.userRepo.Update(ctx, id, update)
	}

	return s.txManager.WithinTransaction(ctx, func(tx *sql.Tx) error {
		if err := s.userRepo.UpdateTx(ctx, tx, id, update); err != nil {
			return err
		}

		if err := s.refreshSessionRepo.RevokeAllTx(ctx, tx, id); err != nil {
			return err
		}

		return nil
	})
}

func (s *UserService) DeleteUser(ctx context.Context, id int64) error {
	return s.userRepo.Delete(ctx, id)
}

func toUserOutput(user model.User) output.UserOutput {
	return output.UserOutput{
		ID:        user.ID,
		Email:     user.Email,
		Nickname:  user.Nickname,
		CreatedAt: user.CreatedAt,
	}
}
