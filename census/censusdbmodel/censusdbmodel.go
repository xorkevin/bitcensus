package censusdbmodel

import (
	"context"
	"time"

	"xorkevin.dev/forge/model/sqldb"
	"xorkevin.dev/kerrors"
)

//go:generate forge model

type (
	// Repo is a content tree repository
	Repo interface {
		New(name string, size int64, modtime int64, hash string) *Model
		Exists(ctx context.Context, name string) (bool, error)
		List(ctx context.Context, limit int, after string) ([]Model, error)
		Get(ctx context.Context, name string) (*Model, error)
		Insert(ctx context.Context, m *Model) error
		Update(ctx context.Context, m *Model) error
		Delete(ctx context.Context, name string) error
		Setup(ctx context.Context) error
	}

	repo struct {
		db        sqldb.Executor
		fileTable *fileModelTable
	}

	// Model is a content tree model
	//forge:model file
	//forge:model:query file
	Model struct {
		Name           string `model:"name,VARCHAR(4095) PRIMARY KEY"`
		Size           int64  `model:"size,BIGINT NOT NULL"`
		ModTime        int64  `model:"mod_time,BIGINT NOT NULL"`
		Hash           string `model:"hash,VARCHAR(2047) NOT NULL"`
		LastVerifiedAt int64  `model:"last_verified_at,BIGINT NOT NULL"`
	}

	//forge:model:query file
	fileProps struct {
		Size           int64  `model:"size,BIGINT NOT NULL"`
		ModTime        int64  `model:"mod_time,BIGINT NOT NULL"`
		Hash           string `model:"hash,VARCHAR(2047) NOT NULL"`
		LastVerifiedAt int64  `model:"last_verified_at,BIGINT NOT NULL"`
	}
)

func New(database sqldb.Executor, fileTable string) Repo {
	return &repo{
		db: database,
		fileTable: &fileModelTable{
			TableName: fileTable,
		},
	}
}

func (r *repo) New(name string, size int64, modtime int64, hash string) *Model {
	return &Model{
		Name:           name,
		Size:           size,
		ModTime:        modtime,
		Hash:           hash,
		LastVerifiedAt: time.Now().Round(0).UnixMilli(),
	}
}

func (r *repo) nameExists(ctx context.Context, d sqldb.Executor, name string) (bool, error) {
	var exists bool
	if err := d.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM "+r.fileTable.TableName+" WHERE name = $1);", name).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

func (r *repo) Exists(ctx context.Context, name string) (bool, error) {
	m, err := r.nameExists(ctx, r.db, name)
	if err != nil {
		return false, kerrors.WithMsg(err, "Failed to check file")
	}
	return m, nil
}

func (r *repo) List(ctx context.Context, limit int, after string) ([]Model, error) {
	if after == "" {
		m, err := r.fileTable.GetModelAll(ctx, r.db, limit, 0)
		if err != nil {
			return nil, kerrors.WithMsg(err, "Failed to get files")
		}
		return m, nil
	}
	m, err := r.fileTable.GetModelGtName(ctx, r.db, after, limit, 0)
	if err != nil {
		return nil, kerrors.WithMsg(err, "Failed to get files")
	}
	return m, nil
}

func (r *repo) Get(ctx context.Context, name string) (*Model, error) {
	m, err := r.fileTable.GetModelByName(ctx, r.db, name)
	if err != nil {
		return nil, kerrors.WithMsg(err, "Failed to get file")
	}
	return m, nil
}

func (r *repo) Insert(ctx context.Context, m *Model) error {
	if err := r.fileTable.Insert(ctx, r.db, m); err != nil {
		return kerrors.WithMsg(err, "Failed to insert file")
	}
	return nil
}

func (r *repo) Update(ctx context.Context, m *Model) error {
	if err := r.fileTable.UpdfilePropsByName(ctx, r.db, &fileProps{
		Size:           m.Size,
		ModTime:        m.ModTime,
		Hash:           m.Hash,
		LastVerifiedAt: m.LastVerifiedAt,
	}, m.Name); err != nil {
		return kerrors.WithMsg(err, "Failed to update file")
	}
	return nil
}

func (r *repo) Delete(ctx context.Context, name string) error {
	if err := r.fileTable.DelByName(ctx, r.db, name); err != nil {
		return kerrors.WithMsg(err, "Failed to delete file")
	}
	return nil
}

func (r *repo) Setup(ctx context.Context) error {
	if err := r.fileTable.Setup(ctx, r.db); err != nil {
		return kerrors.WithMsg(err, "Failed to setup file table")
	}
	return nil
}
