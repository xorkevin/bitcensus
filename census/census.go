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
		Path string          `mapstructure:"path"`
		Dirs []RepoDirConfig `mapstructure:"dirs"`
	}

	SyncConfig struct {
		Repos map[string]RepoConfig `mapstructure:"repos"`
	}
)

func NewCensus(log klog.Logger, dataDir string) *Census {
	hasher := blake2bstream.NewHasher(blake2bstream.Config{})
	algs := map[string]h2streamhash.Hasher{
		hasher.ID(): hasher,
	}
	verifier := h2streamhash.NewVerifier()
	verifier.Register(hasher)
	return &Census{
		log:           klog.NewLevelLogger(log),
		dataDir:       dataDir,
		defaultHasher: hasher,
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

func (c *Census) SyncRepos(ctx context.Context, cfg SyncConfig) error {
	names := make([]string, 0, len(cfg.Repos))
	for k := range cfg.Repos {
		names = append(names, k)
	}
	slices.Sort(names)

	for _, k := range names {
		repoctx := klog.CtxWithAttrs(ctx, klog.AString("repo", k))
		c.log.Info(repoctx, "Syncing repo")
		if err := c.SyncRepo(repoctx, k, cfg.Repos[k]); err != nil {
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

func (c *Census) SyncRepo(ctx context.Context, name string, cfg RepoConfig) error {
	files, err := c.getFilesRepo(ctx, name, "rw")
	if err != nil {
		return kerrors.WithMsg(err, fmt.Sprintf("Failed getting repo %s", name))
	}
	rootDir := kfs.DirFS(cfg.Path)
	for _, i := range cfg.Dirs {
		p := path.Clean(i.Path)
		if i.Exact {
			if err := c.syncRepoFileFS(ctx, files, rootDir, p); err != nil {
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
			if err := c.syncRepoDir(ctx, files, dir, r, p, fs.FileInfoToDirEntry(info)); err != nil {
				return kerrors.WithMsg(err, fmt.Sprintf("Failed to sync dir %s", p))
			}
		}
	}
	return nil
}

func (c *Census) syncRepoDir(ctx context.Context, files censusdbmodel.Repo, dir fs.FS, match *regexp.Regexp, p string, entry fs.DirEntry) error {
	if !entry.IsDir() {
		if !match.MatchString(p) {
			c.log.Debug(ctx, "Skipping unmatched file",
				klog.AString("path", p),
			)
			return nil
		}

		if err := c.syncRepoFileFS(ctx, files, dir, p); err != nil {
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
		if err := c.syncRepoDir(ctx, files, dir, match, path.Join(p, i.Name()), i); err != nil {
			return err
		}
	}
	return nil
}

func (c *Census) syncRepoFileFS(ctx context.Context, files censusdbmodel.Repo, dir fs.FS, p string) error {
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

	existingMatchesSize := existingEntry != nil && info.Size() == existingEntry.Size
	if existingMatchesSize && existingEntry != nil && info.ModTime().Equal(time.Unix(0, existingEntry.ModTime)) {
		c.log.Debug(ctx, "Skipping unchanged file on matching size and modtime",
			klog.AString("path", p),
		)
		return nil
	}

	h, err := c.hashFile(dir, p)
	if err != nil {
		return kerrors.WithMsg(err, "Failed to hash file")
	}

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

	c.log.Info(ctx, "Added file", klog.AString("path", p))
	return nil
}

func (c *Census) hashFile(dir fs.FS, name string) (_ string, retErr error) {
	f, err := dir.Open(name)
	if err != nil {
		return "", kerrors.WithMsg(err, "Failed opening file")
	}
	defer func() {
		if err := f.Close(); err != nil {
			retErr = errors.Join(retErr, kerrors.WithMsg(err, "Failed to close file"))
		}
	}()
	h, err := c.defaultHasher.Hash()
	if err != nil {
		return "", kerrors.WithMsg(err, "Failed creating hash")
	}
	if _, err := io.Copy(h, f); err != nil {
		return "", kerrors.WithMsg(err, "Failed reading file")
	}
	if err := h.Close(); err != nil {
		return "", kerrors.WithMsg(err, "Failed closing stream hash")
	}
	return h.Sum(), nil
}
