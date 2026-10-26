package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Bazu-Bazu/Event-Booking-System/identity-service/internal/apperror"
	"github.com/Bazu-Bazu/Event-Booking-System/identity-service/internal/model"
	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5/pgconn"
)

type UserRepository struct {
	db      *sql.DB
	builder sq.StatementBuilderType
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{
		db:      db,
		builder: sq.StatementBuilder.PlaceholderFormat(sq.Dollar),
	}
}

func (r *UserRepository) Save(ctx context.Context, u model.User) (model.User, error) {
	query := r.builder.Insert("users").
		Columns("email", "nickname", "password_hash").
		Values(u.Email, u.Nickname, u.PasswordHash).
		Suffix("RETURNING id, created_at")

	sqlStr, args, err := query.ToSql()
	if err != nil {
		return model.User{}, fmt.Errorf("build query: %w", err)
	}

	err = r.db.QueryRowContext(ctx, sqlStr, args...).Scan(&u.ID, &u.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			switch pgErr.ConstraintName {
			case "users_email_uidx":
				return model.User{}, apperror.ErrEmailTaken
			case "users_nickname_uidx":
				return model.User{}, apperror.ErrNicknameTaken
			}
		}

		return model.User{}, fmt.Errorf("failed to insert user: %w", err)
	}

	return u, nil
}

func (r *UserRepository) GetByID(ctx context.Context, id int64) (model.User, error) {
	query := r.builder.Select("id", "email", "nickname", "password_hash", "created_at").
		From("users").
		Where(sq.Eq{"id": id})

	sqlStr, args, err := query.ToSql()
	if err != nil {
		return model.User{}, fmt.Errorf("build query: %w", err)
	}

	var u model.User
	err = r.db.QueryRowContext(ctx, sqlStr, args...).Scan(&u.ID, &u.Email, &u.Nickname, &u.PasswordHash, &u.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.User{}, apperror.ErrUserNotFound
		}

		return model.User{}, fmt.Errorf("failed to select user by id: %w", err)
	}

	return u, nil
}

func (r *UserRepository) Delete(ctx context.Context, id int64) error {
	query := r.builder.Delete("users").
		Where(sq.Eq{"id": id})

	sqlStr, args, err := query.ToSql()
	if err != nil {
		return fmt.Errorf("build query: %w", err)
	}

	result, err := r.db.ExecContext(ctx, sqlStr, args...)
	if err != nil {
		return fmt.Errorf("failed to delete user by id: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get deleted rows count: %w", err)
	}

	if rowsAffected == 0 {
		return apperror.ErrUserNotFound
	}

	return nil
}

func (r *UserRepository) Update(ctx context.Context, id int64, update model.UserUpdate) error {
	if update.Email == nil && update.Nickname == nil && update.PasswordHash == nil {
		return apperror.ErrNoFieldsToUpdate
	}

	query := r.builder.Update("users").Where(sq.Eq{"id": id})
	if update.Email != nil {
		query = query.Set("email", *update.Email)
	}
	if update.Nickname != nil {
		query = query.Set("nickname", *update.Nickname)
	}
	if update.PasswordHash != nil {
		query = query.Set("password_hash", *update.PasswordHash)
	}

	sqlStr, args, err := query.ToSql()
	if err != nil {
		return fmt.Errorf("build query: %w", err)
	}

	result, err := r.db.ExecContext(ctx, sqlStr, args...)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			switch pgErr.ConstraintName {
			case "users_email_uidx":
				return apperror.ErrEmailTaken
			case "users_nickname_uidx":
				return apperror.ErrNicknameTaken
			}
		}

		return fmt.Errorf("failed to update user by id: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get updated rows count: %w", err)
	}

	if rowsAffected == 0 {
		return apperror.ErrUserNotFound
	}

	return nil
}
