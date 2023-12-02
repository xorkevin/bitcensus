// Code generated by go generate forge model v0.5.2; DO NOT EDIT.

package censusdbmodel

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"xorkevin.dev/forge/model/sqldb"
)

type (
	fileModelTable struct {
		TableName string
	}
)

func (t *fileModelTable) Setup(ctx context.Context, d sqldb.Executor) error {
	_, err := d.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+t.TableName+" (name VARCHAR(4095) PRIMARY KEY, size BIGINT NOT NULL, mod_time BIGINT NOT NULL, hash VARCHAR(2047) NOT NULL, last_verified_at BIGINT NOT NULL);")
	if err != nil {
		return err
	}
	_, err = d.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS "+t.TableName+"_hash_index ON "+t.TableName+" (hash);")
	if err != nil {
		return err
	}
	return nil
}

func (t *fileModelTable) Insert(ctx context.Context, d sqldb.Executor, m *Model) error {
	_, err := d.ExecContext(ctx, "INSERT INTO "+t.TableName+" (name, size, mod_time, hash, last_verified_at) VALUES ($1, $2, $3, $4, $5);", m.Name, m.Size, m.ModTime, m.Hash, m.LastVerifiedAt)
	if err != nil {
		return err
	}
	return nil
}

func (t *fileModelTable) InsertBulk(ctx context.Context, d sqldb.Executor, models []*Model, allowConflict bool) error {
	conflictSQL := ""
	if allowConflict {
		conflictSQL = " ON CONFLICT DO NOTHING"
	}
	placeholders := make([]string, 0, len(models))
	args := make([]interface{}, 0, len(models)*5)
	for c, m := range models {
		n := c * 5
		placeholders = append(placeholders, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d)", n+1, n+2, n+3, n+4, n+5))
		args = append(args, m.Name, m.Size, m.ModTime, m.Hash, m.LastVerifiedAt)
	}
	_, err := d.ExecContext(ctx, "INSERT INTO "+t.TableName+" (name, size, mod_time, hash, last_verified_at) VALUES "+strings.Join(placeholders, ", ")+conflictSQL+";", args...)
	if err != nil {
		return err
	}
	return nil
}

func (t *fileModelTable) GetModelByName(ctx context.Context, d sqldb.Executor, name string) (*Model, error) {
	m := &Model{}
	if err := d.QueryRowContext(ctx, "SELECT name, size, mod_time, hash, last_verified_at FROM "+t.TableName+" WHERE name = $1;", name).Scan(&m.Name, &m.Size, &m.ModTime, &m.Hash, &m.LastVerifiedAt); err != nil {
		return nil, err
	}
	return m, nil
}

func (t *fileModelTable) DelByName(ctx context.Context, d sqldb.Executor, name string) error {
	_, err := d.ExecContext(ctx, "DELETE FROM "+t.TableName+" WHERE name = $1;", name)
	return err
}

func (t *fileModelTable) GetModelAll(ctx context.Context, d sqldb.Executor, limit, offset int) (_ []Model, retErr error) {
	res := make([]Model, 0, limit)
	rows, err := d.QueryContext(ctx, "SELECT name, size, mod_time, hash, last_verified_at FROM "+t.TableName+" ORDER BY name LIMIT $1 OFFSET $2;", limit, offset)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("Failed to close db rows: %w", err))
		}
	}()
	for rows.Next() {
		var m Model
		if err := rows.Scan(&m.Name, &m.Size, &m.ModTime, &m.Hash, &m.LastVerifiedAt); err != nil {
			return nil, err
		}
		res = append(res, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return res, nil
}

func (t *fileModelTable) GetModelGtName(ctx context.Context, d sqldb.Executor, name string, limit, offset int) (_ []Model, retErr error) {
	res := make([]Model, 0, limit)
	rows, err := d.QueryContext(ctx, "SELECT name, size, mod_time, hash, last_verified_at FROM "+t.TableName+" WHERE name > $3 ORDER BY name LIMIT $1 OFFSET $2;", limit, offset, name)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("Failed to close db rows: %w", err))
		}
	}()
	for rows.Next() {
		var m Model
		if err := rows.Scan(&m.Name, &m.Size, &m.ModTime, &m.Hash, &m.LastVerifiedAt); err != nil {
			return nil, err
		}
		res = append(res, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return res, nil
}

func (t *fileModelTable) UpdfilePropsByName(ctx context.Context, d sqldb.Executor, m *fileProps, name string) error {
	_, err := d.ExecContext(ctx, "UPDATE "+t.TableName+" SET (size, mod_time, hash, last_verified_at) = ($1, $2, $3, $4) WHERE name = $5;", m.Size, m.ModTime, m.Hash, m.LastVerifiedAt, name)
	if err != nil {
		return err
	}
	return nil
}
