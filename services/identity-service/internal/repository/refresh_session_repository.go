package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Bazu-Bazu/Event-Booking-System/identity-service/internal/apperror"
	"github.com/Bazu-Bazu/Event-Booking-System/identity-service/internal/model"
	sq "github.com/Masterminds/squirrel"
)

type RefreshSessionRepository struct {
	db      *sql.DB
	builder sq.StatementBuilderType
}

func NewRefreshSessionRepository(db *sql.DB) *RefreshSessionRepository {
	return &RefreshSessionRepository{
		db:      db,
		builder: sq.StatementBuilder.PlaceholderFormat(sq.Dollar),
	}
}

func (r *RefreshSessionRepository) CreateWithLimit(ctx context.Context, session model.RefreshSession) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin create refresh session: %w", err)
	}
	defer tx.Rollback()

	if err := r.lockUser(ctx, session, tx); err != nil {
		return err
	}
	if err := r.deleteExpiredSessions(ctx, session, tx); err != nil {
		return err
	}
	if err := r.deleteOverLimitSessions(ctx, session, tx); err != nil {
		return err
	}
	if err := r.saveNewSession(ctx, session, tx); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

func (r *RefreshSessionRepository) lockUser(ctx context.Context, session model.RefreshSession, tx *sql.Tx) error {
	query := r.builder.
		Select("id").
		From("users").
		Where(sq.Eq{"id": session.UserID}).
		Suffix("FOR UPDATE")
	sqlStr, args, err := query.ToSql()
	if err != nil {
		return fmt.Errorf("build query: %w", err)
	}

	var userID int64
	if err = tx.QueryRowContext(ctx, sqlStr, args...).Scan(&userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return apperror.ErrUserNotFound
		}

		return fmt.Errorf("lock user: %w", err)
	}

	return nil
}

func (r *RefreshSessionRepository) deleteExpiredSessions(ctx context.Context, session model.RefreshSession, tx *sql.Tx) error {
	query := r.builder.
		Delete("refresh_sessions").
		Where(sq.Eq{"user_id": session.UserID}).
		Where(sq.Or{
			sq.Expr("expires_at <= NOW()"),
			sq.NotEq{"revoked_at": nil},
		})
	sqlStr, args, err := query.ToSql()
	if err != nil {
		return fmt.Errorf("build query: %w", err)
	}

	if _, err := tx.ExecContext(ctx, sqlStr, args...); err != nil {
		return fmt.Errorf("delete inactive sessions: %w", err)
	}

	return nil
}

func (r *RefreshSessionRepository) deleteOverLimitSessions(ctx context.Context, session model.RefreshSession, tx *sql.Tx) error {
	subquery := r.builder.
		Select("id").
		From("refresh_sessions").
		Where(sq.Eq{"user_id": session.UserID}).
		OrderBy("created_at DESC", "id DESC").
		Offset(4)

	query := r.builder.
		Delete("refresh_sessions").
		Where(sq.Expr("id IN (?)", subquery))

	sqlStr, args, err := query.ToSql()
	if err != nil {
		return fmt.Errorf("build query: %w", err)
	}

	if _, err := tx.ExecContext(ctx, sqlStr, args...); err != nil {
		return fmt.Errorf("delete old sessions: %w", err)
	}

	return nil
}

func (r *RefreshSessionRepository) saveNewSession(ctx context.Context, session model.RefreshSession, tx *sql.Tx) error {
	query := r.builder.
		Insert("refresh_sessions").
		Columns("user_id", "token_hash", "expires_at").
		Values(session.UserID, session.TokenHash, session.ExpiresAt)

	sqlStr, args, err := query.ToSql()
	if err != nil {
		return fmt.Errorf("build query: %w", err)
	}

	if _, err := tx.ExecContext(ctx, sqlStr, args...); err != nil {
		return fmt.Errorf("insert refresh session: %w", err)
	}

	return nil
}

func (r *RefreshSessionRepository) Rotate(ctx context.Context, oldTokenHash string, newTokenHash string, newExpiresAt time.Time) (int64, error) {
	query := r.builder.
		Update("refresh_sessions").
		Set("token_hash", newTokenHash).
		Set("expires_at", newExpiresAt).
		Where(sq.Eq{"token_hash": oldTokenHash}).
		Where(sq.Eq{"revoked_at": nil}).
		Where(sq.Expr("expires_at > NOW()")).
		Suffix("RETURNING user_id")

	sqlStr, args, err := query.ToSql()
	if err != nil {
		return 0, fmt.Errorf("build query: %w", err)
	}

	var userID int64
	err = r.db.QueryRowContext(ctx, sqlStr, args...).Scan(&userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, apperror.ErrInvalidRefreshToken
		}
		return 0, fmt.Errorf("rotate refresh token: %w", err)
	}

	return userID, nil
}

func (r *RefreshSessionRepository) Revoke(ctx context.Context, tokenHash string) error {
	query := r.builder.
		Update("refresh_sessions").
		Set("revoked_at", sq.Expr("NOW()")).
		Where(sq.Eq{"token_hash": tokenHash}).
		Where(sq.Eq{"revoked_at": nil})

	sqlStr, args, err := query.ToSql()
	if err != nil {
		return fmt.Errorf("build query: %w", err)
	}

	result, err := r.db.ExecContext(ctx, sqlStr, args...)
	if err != nil {
		return fmt.Errorf("revoke refresh session: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get revoked sessions count: %w", err)
	}

	if rowsAffected == 0 {
		return apperror.ErrInvalidRefreshToken
	}

	return nil
}

func (r *RefreshSessionRepository) RevokeAll(ctx context.Context, userID int64) error {
	return r.revokeAll(ctx, r.db, userID)
}

func (r *RefreshSessionRepository) RevokeAllTx(ctx context.Context, tx *sql.Tx, userID int64) error {
	return r.revokeAll(ctx, tx, userID)
}

func (r *RefreshSessionRepository) revokeAll(ctx context.Context, executor sqlExecer, userID int64) error {
	query := r.builder.
		Update("refresh_sessions").
		Set("revoked_at", sq.Expr("NOW()")).
		Where(sq.Eq{"user_id": userID}).
		Where(sq.Eq{"revoked_at": nil})

	sqlStr, args, err := query.ToSql()
	if err != nil {
		return fmt.Errorf("build query: %w", err)
	}

	if _, err := executor.ExecContext(ctx, sqlStr, args...); err != nil {
		return fmt.Errorf("revoke all sessions for user: %w", err)
	}

	return nil
}
