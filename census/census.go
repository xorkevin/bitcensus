package census

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"path"
	"regexp"
	"slices"
	"time"

	"xorkevin.dev/bitcensus/census/censusdbmodel"
	"xorkevin.dev/bitcensus/dbsql"
	"xorkevin.dev/hunter2/h2streamhash"
	"xorkevin.dev/hunter2/h2streamhash/blake2bstream"
	"xorkevin.dev/hunter2/h2streamhash/sha256stream"
	"xorkevin.dev/kerrors"
	"xorkevin.dev/kfs"
	"xorkevin.dev/klog"
)

// ErrNotFound is returned when a file is not found
var ErrNotFound errNotFound

type (
	errNotFound struct{}
)

func (e errNotFound) Error() string {
	return "File not found"
}

type (
	Census struct {
		log           *klog.LevelLogger
		dataDir       string
		defaultHasher h2streamhash.Hasher
		hashers       map[string]h2streamhash.Hasher
		verifier      *h2streamhash.Verifier
	}

	RepoDirConfig struct {
		Exact bool   `mapstructure:"exact"`
		Path  string `mapstructure:"path"`
		Match string `mapstructure:"match"`
	}

	RepoConfig struct {
		Path    string          `mapstructure:"path"`
		Dirs    []RepoDirConfig `mapstructure:"dirs"`
		HashAlg string          `mapstructure:"hash_alg"`
	}

	SyncConfig struct {
		Repos map[string]RepoConfig `mapstructure:"repos"`
	}

	SyncFlags struct {
		RmAfter bool
		Force   bool
		DryRun  bool
	}

	VerifyFlags struct {
		After time.Time
		Force bool
	}
)

func NewCensus(log klog.Logger, dataDir string) *Census {
	b2sum := blake2bstream.NewHasher(blake2bstream.Config{})
	sha256sum := sha256stream.NewHasher(sha256stream.Config{})
	algs := map[string]h2streamhash.Hasher{
		b2sum.ID():     b2sum,
		sha256sum.ID(): sha256sum,
	}
	verifier := h2streamhash.NewVerifier()
	verifier.Register(b2sum)
	verifier.Register(sha256sum)
	return &Census{
		log:           klog.NewLevelLogger(log),
		dataDir:       dataDir,
		defaultHasher: b2sum,
		hashers:       algs,
		verifier:      verifier,
	}
}

func (c *Census) getFilesRepo(ctx context.Context, name string, mode string) (censusdbmodel.Repo, error) {
	// url must be in the form of
	// file:rel/path/to/file.db?optquery=value&otheroptquery=value
	u := url.URL{
		Scheme: "file",
		Opaque: path.Join(c.dataDir, "db", name+".db"),
	}
	q := u.Query()
	q.Set("mode", mode)
	u.RawQuery = q.Encode()
	d := dbsql.NewSQLClient(c.log.Logger.Sublogger("db"), u.String())
	if err := d.Init(); err != nil {
		return nil, kerrors.WithMsg(err, "Failed to init sqlite db client")
	}

	c.log.Info(context.Background(), "Using statedb",
		klog.AString("db.engine", "sqlite"),
		klog.AString("db.file", u.Opaque),
	)

	files := censusdbmodel.New(d, "files")

	if mode == "rw" {
		if err := files.Setup(ctx); err != nil {
			return nil, kerrors.WithMsg(err, "Failed setting up files table")
		}
	}

	return files, nil
}

func (c *Census) SyncRepos(ctx context.Context, cfg SyncConfig, flags SyncFlags) error {
	names := make([]string, 0, len(cfg.Repos))
	for k := range cfg.Repos {
		names = append(names, k)
	}
	slices.Sort(names)

	for _, k := range names {
		repoctx := klog.CtxWithAttrs(ctx, klog.AString("repo", k))
		c.log.Info(repoctx, "Syncing repo")
		if err := c.SyncRepo(repoctx, k, cfg.Repos[k], flags); err != nil {
			return kerrors.WithMsg(err, fmt.Sprintf("Failed syncing repo %s", k))
		}
	}
	return nil
}

func (c *Census) getExistingEntry(ctx context.Context, files censusdbmodel.Repo, p string) (*censusdbmodel.Model, error) {
	m, err := files.Get(ctx, p)
	if err != nil {
		if !errors.Is(err, dbsql.ErrNotFound) {
			return nil, kerrors.WithMsg(err, "Failed getting file from db")
		}
		return nil, nil
	}
	return m, nil
}

const (
	sqliteFileBatchSize = 32
)

func (c *Census) SyncRepo(ctx context.Context, name string, cfg RepoConfig, flags SyncFlags) error {
	hasher := c.defaultHasher
	if cfg.HashAlg != "" {
		hasher = c.hashers[cfg.HashAlg]
	}

	files, err := c.getFilesRepo(ctx, name, "rw")
	if err != nil {
		return kerrors.WithMsg(err, fmt.Sprintf("Failed getting repo %s", name))
	}

	for _, i := range cfg.Dirs {
		if !i.Exact {
			p := path.Clean(i.Path)
			if _, err := regexp.Compile(i.Match); err != nil {
				return kerrors.WithMsg(err, fmt.Sprintf("Invalid match regex for dir %s", p))
			}
		}
	}

	rootDir := kfs.DirFS(cfg.Path)

	for _, i := range cfg.Dirs {
		p := path.Clean(i.Path)
		if i.Exact {
			if err := c.syncRepoFileFS(ctx, files, hasher, rootDir, p, flags); err != nil {
				return kerrors.WithMsg(err, fmt.Sprintf("Failed to sync file %s", p))
			}
		} else {
			dir, err := fs.Sub(rootDir, p)
			if err != nil {
				return kerrors.WithMsg(err, fmt.Sprintf("Failed to get sub directory %s", p))
			}
			r, err := regexp.Compile(i.Match)
			if err != nil {
				return kerrors.WithMsg(err, fmt.Sprintf("Invalid match regex for dir %s", p))
			}
			info, err := fs.Stat(dir, ".")
			if err != nil {
				return kerrors.WithMsg(err, fmt.Sprintf("Failed to stat dir %s", p))
			}
			if err := c.syncRepoDir(ctx, files, hasher, dir, r, p, fs.FileInfoToDirEntry(info), flags); err != nil {
				return kerrors.WithMsg(err, fmt.Sprintf("Failed to sync dir %s", p))
			}
		}
	}

	if flags.RmAfter {
		cursor := ""
		for {
			m, err := files.List(ctx, sqliteFileBatchSize, cursor)
			if err != nil {
				return kerrors.WithMsg(err, "Failed to list db files")
			}
			if len(m) == 0 {
				break
			}
			for _, i := range m {
				if _, err := fs.Stat(rootDir, i.Name); err != nil {
					if !errors.Is(err, fs.ErrNotExist) {
						return kerrors.WithMsg(err, fmt.Sprintf("Failed to stat file %s", i.Name))
					}
					if !flags.DryRun {
						if err := files.Delete(ctx, i.Name); err != nil {
							return kerrors.WithMsg(err, fmt.Sprintf("Failed deleting file entry %s", i.Name))
						}
					}
					c.log.Info(ctx, "Deleted file", klog.AString("path", i.Name))
				}
			}
			if len(m) < sqliteFileBatchSize {
				break
			}
			cursor = m[len(m)-1].Name
		}
	}

	return nil
}

func (c *Census) syncRepoDir(ctx context.Context, files censusdbmodel.Repo, hasher h2streamhash.Hasher, dir fs.FS, match *regexp.Regexp, p string, entry fs.DirEntry, flags SyncFlags) error {
	if !entry.IsDir() {
		if !match.MatchString(p) {
			c.log.Debug(ctx, "Skipping unmatched file",
				klog.AString("path", p),
			)
			return nil
		}

		if err := c.syncRepoFileFS(ctx, files, hasher, dir, p, flags); err != nil {
			return kerrors.WithMsg(err, fmt.Sprintf("Failed to sync file %s", p))
		}
		return nil
	}
	entries, err := fs.ReadDir(dir, p)
	if err != nil {
		return kerrors.WithMsg(err, fmt.Sprintf("Failed reading dir %s", p))
	}
	c.log.Debug(ctx, "Exploring dir",
		klog.AString("path", p),
	)
	for _, i := range entries {
		if err := c.syncRepoDir(ctx, files, hasher, dir, match, path.Join(p, i.Name()), i, flags); err != nil {
			return err
		}
	}
	return nil
}

func (c *Census) syncRepoFileFS(ctx context.Context, files censusdbmodel.Repo, hasher h2streamhash.Hasher, dir fs.FS, p string, flags SyncFlags) error {
	info, err := fs.Stat(dir, p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return kerrors.WithKind(err, ErrNotFound, "File does not exist")
		}
		return kerrors.WithMsg(err, "Failed to stat file")
	}
	if info.IsDir() {
		return kerrors.WithMsg(nil, "File is dir")
	}

	existingEntry, err := c.getExistingEntry(ctx, files, p)
	if err != nil {
		return err
	}

	if !flags.Force {
		if existingEntry != nil && info.Size() == existingEntry.Size && info.ModTime().Equal(time.Unix(0, existingEntry.ModTime)) {
			c.log.Debug(ctx, "Skipping unchanged file on matching size and modtime",
				klog.AString("path", p),
			)
			return nil
		}
	}

	h, err := c.hashFile(hasher, dir, p, existingEntry)
	if err != nil {
		return kerrors.WithMsg(err, "Failed to hash file")
	}

	if !flags.DryRun {
		m := files.New(p, info.Size(), info.ModTime().UnixNano(), h)
		if existingEntry == nil {
			if err := files.Insert(ctx, m); err != nil {
				return kerrors.WithMsg(err, "Failed adding file entry")
			}
		} else {
			if err := files.Update(ctx, m); err != nil {
				return kerrors.WithMsg(err, "Failed updating file entry")
			}
		}
	}
	c.log.Info(ctx, "Added file", klog.AString("path", p))

	return nil
}

func (c *Census) hashFile(hasher h2streamhash.Hasher, dir fs.FS, name string, existingEntry *censusdbmodel.Model) (_ string, retErr error) {
	var h h2streamhash.Hash
	if existingEntry != nil {
		var err error
		h, err = c.verifier.Verify(existingEntry.Hash)
		if err != nil {
			return "", kerrors.WithMsg(err, "Failed creating hash")
		}
	} else {
		var err error
		h, err = hasher.Hash()
		if err != nil {
			return "", kerrors.WithMsg(err, "Failed creating hash")
		}
	}
	if err := c.readFile(h, dir, name); err != nil {
		return "", err
	}
	if err := h.Close(); err != nil {
		return "", kerrors.WithMsg(err, "Failed closing stream hash")
	}
	return h.Sum(), nil
}

func (c *Census) VerifyRepo(ctx context.Context, name string, cfg RepoConfig, flags VerifyFlags) error {
	hasher := c.defaultHasher
	if cfg.HashAlg != "" {
		hasher = c.hashers[cfg.HashAlg]
	}

	files, err := c.getFilesRepo(ctx, name, "rw")
	if err != nil {
		return kerrors.WithMsg(err, fmt.Sprintf("Failed getting repo %s", name))
	}

	rootDir := kfs.DirFS(cfg.Path)

	cursor := ""
	for {
		m, err := files.List(ctx, sqliteFileBatchSize, cursor)
		if err != nil {
			return kerrors.WithMsg(err, "Failed to list db files")
		}
		if len(m) == 0 {
			break
		}
		for _, i := range m {
			if flags.After.After(time.UnixMilli(i.LastVerifiedAt)) {
				continue
			}

			info, err := fs.Stat(rootDir, i.Name)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return kerrors.WithKind(err, ErrNotFound, "File does not exist")
				}
				return kerrors.WithMsg(err, fmt.Sprintf("Failed to stat file %s", i.Name))
			}
			h, err := c.verifyFile(hasher, rootDir, i.Name, i, flags.Force)
			if err != nil {
				return kerrors.WithMsg(err, fmt.Sprintf("Failed to verify file %s", i.Name))
			}
			if err := files.Update(ctx, files.New(i.Name, info.Size(), info.ModTime().UnixNano(), h)); err != nil {
				return kerrors.WithMsg(err, "Failed updating file entry")
			}
		}
		if len(m) < sqliteFileBatchSize {
			break
		}
		cursor = m[len(m)-1].Name
	}

	return nil
}

func (c *Census) verifyFile(hasher h2streamhash.Hasher, dir fs.FS, name string, existingEntry censusdbmodel.Model, force bool) (_ string, retErr error) {
	vh, err := c.verifier.Verify(existingEntry.Hash)
	if err != nil {
		return "", kerrors.WithMsg(err, "Failed creating hash")
	}
	h := vh
	var w io.Writer = vh
	if force && hasher.ID() != vh.ID() {
		var err error
		h, err = hasher.Hash()
		if err != nil {
			return "", kerrors.WithMsg(err, "Failed creating hash")
		}
		w = io.MultiWriter(vh, h)
	}
	if err := c.readFile(w, dir, name); err != nil {
		return "", err
	}
	if err := vh.Close(); err != nil {
		return "", kerrors.WithMsg(err, "Failed closing stream hash")
	}
	if err := h.Close(); err != nil {
		return "", kerrors.WithMsg(err, "Failed closing stream hash")
	}
	if ok, err := vh.Verify(existingEntry.Hash); err != nil {
		return "", kerrors.WithMsg(err, "Failed verifying checksum")
	} else if !ok {
		return "", kerrors.WithMsg(nil, "Checksum does not match")
	}
	return h.Sum(), nil
}

func (c *Census) readFile(dest io.Writer, dir fs.FS, name string) (retErr error) {
	f, err := dir.Open(name)
	if err != nil {
		return kerrors.WithMsg(err, "Failed opening file")
	}
	defer func() {
		if err := f.Close(); err != nil {
			retErr = errors.Join(retErr, kerrors.WithMsg(err, "Failed to close file"))
		}
	}()
	if _, err := io.Copy(dest, f); err != nil {
		return kerrors.WithMsg(err, "Failed reading file")
	}
	return nil
}
