package census

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"xorkevin.dev/bitcensus/census/censusdbmodel"
	"xorkevin.dev/bitcensus/dbsql"
	"xorkevin.dev/bitcensus/util/bytefmt"
	"xorkevin.dev/hunter2/h2streamhash"
	"xorkevin.dev/hunter2/h2streamhash/blake2bstream"
	"xorkevin.dev/hunter2/h2streamhash/blake3stream"
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
	ChecksumError struct {
		Repo     string
		Mismatch []string
	}
)

func (e *ChecksumError) Error() string {
	return "Checksum error"
}

type (
	Census struct {
		log           *klog.LevelLogger
		dataDir       string
		cfg           SyncConfig
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

	SyncConfig map[string]RepoConfig

	SyncFlags struct {
		Prune  bool
		Force  bool
		DryRun bool
	}

	VerifyFlags struct {
		Before  time.Time
		Upgrade bool
	}
)

func New(log klog.Logger, dataDir string, cfg SyncConfig) *Census {
	b3sum := blake3stream.NewHasher(blake3stream.Config{})
	b2sum := blake2bstream.NewHasher(blake2bstream.Config{})
	sha256sum := sha256stream.NewHasher(sha256stream.Config{})
	algs := map[string]h2streamhash.Hasher{
		b3sum.ID():     b3sum,
		b2sum.ID():     b2sum,
		sha256sum.ID(): sha256sum,
	}
	verifier := h2streamhash.NewVerifier()
	verifier.Register(b3sum)
	verifier.Register(b2sum)
	verifier.Register(sha256sum)
	return &Census{
		log:           klog.NewLevelLogger(log),
		dataDir:       dataDir,
		cfg:           cfg,
		defaultHasher: b3sum,
		hashers:       algs,
		verifier:      verifier,
	}
}

func (c *Census) getFilesRepo(ctx context.Context, name string, mode string) (censusdbmodel.Repo, *dbsql.SQLClient, error) {
	// url must be in the form of
	// file:rel/path/to/file.db?optquery=value&otheroptquery=value
	dir := path.Join(c.dataDir, "db")
	u := path.Join(dir, name+".db")
	q := url.Values{}
	q.Set("mode", mode)
	dsn := fmt.Sprintf("file:%s?%s", filepath.FromSlash(u), q.Encode())
	if err := os.MkdirAll(filepath.FromSlash(dir), 0o777); err != nil {
		return nil, nil, kerrors.WithMsg(err, "Failed to mkdir for db")
	}
	d := dbsql.NewSQLClient(c.log.Logger.Sublogger("db"), dsn)
	if err := d.Init(); err != nil {
		return nil, nil, kerrors.WithMsg(err, "Failed to init sqlite db client")
	}

	c.log.Info(context.Background(), "Using statedb",
		klog.AString("db.engine", "sqlite"),
		klog.AString("db.file", u),
	)

	files := censusdbmodel.New(d, "files")

	return files, d, nil
}

func (c *Census) SyncRepos(ctx context.Context, flags SyncFlags) error {
	names := make([]string, 0, len(c.cfg))
	for k := range c.cfg {
		names = append(names, k)
	}
	slices.Sort(names)

	for _, k := range names {
		repoctx := klog.CtxWithAttrs(ctx, klog.AString("repo", k))
		c.log.Info(repoctx, "Syncing repo")
		if err := c.SyncRepo(repoctx, k, flags); err != nil {
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

func (c *Census) SyncRepo(ctx context.Context, name string, flags SyncFlags) (retErr error) {
	cfg, ok := c.cfg[name]
	if !ok {
		return kerrors.WithMsg(nil, fmt.Sprintf("Invalid repo %s", name))
	}

	hasher := c.defaultHasher
	if cfg.HashAlg != "" {
		hasher = c.hashers[cfg.HashAlg]
	}

	files, d, err := c.getFilesRepo(ctx, name, "rwc")
	if err != nil {
		return kerrors.WithMsg(err, fmt.Sprintf("Failed getting repo %s", name))
	}
	defer func() {
		if err := d.Close(); err != nil {
			retErr = errors.Join(retErr, kerrors.WithMsg(err, "Failed to close sql client"))
		}
	}()
	if err := files.Setup(ctx); err != nil {
		return kerrors.WithMsg(err, "Failed setting up files table")
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
			c.log.Debug(ctx, "Adding repo file",
				klog.AString("repopath", cfg.Path),
				klog.AString("repofilepath", p),
			)
			if err := c.syncRepoFileFS(ctx, files, hasher, rootDir, p, flags); err != nil {
				return kerrors.WithMsg(err, fmt.Sprintf("Failed to sync file %s", p))
			}
		} else {
			c.log.Debug(ctx, "Exploring repo dir",
				klog.AString("repopath", cfg.Path),
				klog.AString("repodirpath", p),
			)
			r, err := regexp.Compile(i.Match)
			if err != nil {
				return kerrors.WithMsg(err, fmt.Sprintf("Invalid match regex for dir %s", p))
			}
			info, err := fs.Stat(rootDir, p)
			if err != nil {
				return kerrors.WithMsg(err, fmt.Sprintf("Failed to stat dir %s", p))
			}
			if err := c.syncRepoDir(ctx, files, hasher, rootDir, r, p, fs.FileInfoToDirEntry(info), flags); err != nil {
				return kerrors.WithMsg(err, fmt.Sprintf("Failed to sync dir %s", p))
			}
		}
	}

	if flags.Prune {
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
					c.log.Info(ctx, "Deleting file entry", klog.AString("path", i.Name))
					if !flags.DryRun {
						if err := files.Delete(ctx, i.Name); err != nil {
							return kerrors.WithMsg(err, fmt.Sprintf("Failed deleting file entry %s", i.Name))
						}
						c.log.Info(ctx, "Deleted file entry", klog.AString("path", i.Name))
					}
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

	c.log.Info(ctx, "Adding file",
		klog.AString("path", p),
		klog.AString("size", bytefmt.ToString(float64(info.Size()))),
	)
	if !flags.DryRun {
		start := time.Now()
		h, err := c.hashFile(hasher, dir, p, existingEntry)
		if err != nil {
			return kerrors.WithMsg(err, "Failed to hash file")
		}
		duration := time.Since(start)

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

		c.log.Info(ctx, "Added file",
			klog.AString("path", p),
			klog.AString("size", bytefmt.ToString(float64(info.Size()))),
			klog.AString("hashrate", humanHashRate(info.Size(), duration)),
		)
	}

	return nil
}

func humanHashRate(size int64, duration time.Duration) string {
	return bytefmt.ToString(float64(size)/duration.Seconds()) + "/s"
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

func (c *Census) VerifyRepos(ctx context.Context, flags VerifyFlags) error {
	names := make([]string, 0, len(c.cfg))
	for k := range c.cfg {
		names = append(names, k)
	}
	slices.Sort(names)

	for _, k := range names {
		repoctx := klog.CtxWithAttrs(ctx, klog.AString("repo", k))
		c.log.Info(repoctx, "Verifying repo")
		if err := c.VerifyRepo(repoctx, k, flags); err != nil {
			return kerrors.WithMsg(err, fmt.Sprintf("Failed verifying repo %s", k))
		}
	}
	return nil
}

func (c *Census) VerifyRepo(ctx context.Context, name string, flags VerifyFlags) (retErr error) {
	cfg, ok := c.cfg[name]
	if !ok {
		return kerrors.WithMsg(nil, fmt.Sprintf("Invalid repo %s", name))
	}

	hasher := c.defaultHasher
	if cfg.HashAlg != "" {
		hasher = c.hashers[cfg.HashAlg]
	}

	files, d, err := c.getFilesRepo(ctx, name, "rw")
	if err != nil {
		return kerrors.WithMsg(err, fmt.Sprintf("Failed getting repo %s", name))
	}
	defer func() {
		if err := d.Close(); err != nil {
			retErr = errors.Join(retErr, kerrors.WithMsg(err, "Failed to close sql client"))
		}
	}()
	if err := files.Setup(ctx); err != nil {
		return kerrors.WithMsg(err, "Failed setting up files table")
	}

	var mismatch []string

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
			if !flags.Before.IsZero() && !time.UnixMilli(i.LastVerifiedAt).Before(flags.Before) {
				c.log.Debug(ctx, "Skipping recently verified file", klog.AString("path", i.Name))
				continue
			}

			info, err := fs.Stat(rootDir, i.Name)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return kerrors.WithKind(err, ErrNotFound, "File does not exist")
				}
				return kerrors.WithMsg(err, fmt.Sprintf("Failed to stat file %s", i.Name))
			}
			c.log.Info(ctx, "Verifying file",
				klog.AString("path", i.Name),
				klog.AString("size", bytefmt.ToString(float64(info.Size()))),
			)
			start := time.Now()
			match, h, err := c.verifyFile(hasher, rootDir, i.Name, i, flags.Upgrade)
			if err != nil {
				return kerrors.WithMsg(err, fmt.Sprintf("Failed to verify file %s", i.Name))
			}
			duration := time.Since(start)
			if match {
				if err := files.Update(ctx, files.New(i.Name, info.Size(), info.ModTime().UnixNano(), h)); err != nil {
					return kerrors.WithMsg(err, "Failed updating file entry")
				}
				c.log.Info(ctx, "Verified file",
					klog.AString("path", i.Name),
					klog.AString("size", bytefmt.ToString(float64(info.Size()))),
					klog.AString("hashrate", humanHashRate(info.Size(), duration)),
				)
			} else {
				c.log.Warn(ctx, "Checksum mismatch",
					klog.AString("path", i.Name),
					klog.AString("size", bytefmt.ToString(float64(info.Size()))),
					klog.AString("hashrate", humanHashRate(info.Size(), duration)),
				)
				mismatch = append(mismatch, i.Name)
			}
		}
		if len(m) < sqliteFileBatchSize {
			break
		}
		cursor = m[len(m)-1].Name
	}

	if len(mismatch) != 0 {
		return &ChecksumError{
			Repo:     name,
			Mismatch: mismatch,
		}
	}

	return nil
}

func (c *Census) verifyFile(hasher h2streamhash.Hasher, dir fs.FS, name string, existingEntry censusdbmodel.Model, force bool) (_ bool, _ string, retErr error) {
	vh, err := c.verifier.Verify(existingEntry.Hash)
	if err != nil {
		return false, "", kerrors.WithMsg(err, "Failed creating hash")
	}
	h := vh
	var w io.Writer = vh
	if force && hasher.ID() != vh.ID() {
		var err error
		h, err = hasher.Hash()
		if err != nil {
			return false, "", kerrors.WithMsg(err, "Failed creating hash")
		}
		w = io.MultiWriter(vh, h)
	}
	if err := c.readFile(w, dir, name); err != nil {
		return false, "", err
	}
	if err := vh.Close(); err != nil {
		return false, "", kerrors.WithMsg(err, "Failed closing stream hash")
	}
	if err := h.Close(); err != nil {
		return false, "", kerrors.WithMsg(err, "Failed closing stream hash")
	}
	ok, err := vh.Verify(existingEntry.Hash)
	if err != nil {
		return false, "", kerrors.WithMsg(err, "Failed verifying checksum")
	}
	return ok, h.Sum(), nil
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

type (
	FileEntry struct {
		Name     string `json:"name"`
		Size     int64  `json:"size"`
		ModTime  int64  `json:"mod_time"`
		Checksum string `json:"checksum"`
	}
)

func (c *Census) ExportRepo(ctx context.Context, w io.Writer, name string) (retErr error) {
	if _, ok := c.cfg[name]; !ok {
		return kerrors.WithMsg(nil, fmt.Sprintf("Invalid repo %s", name))
	}

	files, d, err := c.getFilesRepo(ctx, name, "ro")
	if err != nil {
		return kerrors.WithMsg(err, fmt.Sprintf("Failed getting repo %s", name))
	}
	defer func() {
		if err := d.Close(); err != nil {
			retErr = errors.Join(retErr, kerrors.WithMsg(err, "Failed to close sql client"))
		}
	}()

	j := json.NewEncoder(w)

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
			if err := j.Encode(FileEntry{
				Name:     i.Name,
				Size:     i.Size,
				ModTime:  i.ModTime,
				Checksum: i.Hash,
			}); err != nil {
				return kerrors.WithMsg(err, "Failed encoding file entry")
			}
		}
		if len(m) < sqliteFileBatchSize {
			break
		}
		cursor = m[len(m)-1].Name
	}

	return nil
}

func (c *Census) ImportRepo(ctx context.Context, r io.Reader, name string, override bool) (retErr error) {
	if _, ok := c.cfg[name]; !ok {
		return kerrors.WithMsg(nil, fmt.Sprintf("Invalid repo %s", name))
	}

	files, d, err := c.getFilesRepo(ctx, name, "rwc")
	if err != nil {
		return kerrors.WithMsg(err, fmt.Sprintf("Failed getting repo %s", name))
	}
	defer func() {
		if err := d.Close(); err != nil {
			retErr = errors.Join(retErr, kerrors.WithMsg(err, "Failed to close sql client"))
		}
	}()
	if err := files.Setup(ctx); err != nil {
		return kerrors.WithMsg(err, "Failed setting up files table")
	}

	j := json.NewDecoder(r)
	for j.More() {
		var entry FileEntry
		if err := j.Decode(&entry); err != nil {
			return kerrors.WithMsg(err, "Malformed file entry")
		}
		if entry.Name == "" {
			return kerrors.WithMsg(err, "File entry missing name")
		}
		if m, err := files.Get(ctx, entry.Name); err != nil {
			if !errors.Is(err, dbsql.ErrNotFound) {
				return kerrors.WithMsg(err, "Failed getting file from db")
			}
			m = files.New(entry.Name, entry.Size, entry.ModTime, entry.Checksum)
			m.LastVerifiedAt = 0
			if err := files.Insert(ctx, m); err != nil {
				return kerrors.WithMsg(err, "Failed adding file entry")
			}
		} else {
			if override {
				m.Size = entry.Size
				m.ModTime = entry.ModTime
				m.Hash = entry.Checksum
				m.LastVerifiedAt = 0
				if err := files.Update(ctx, m); err != nil {
					return kerrors.WithMsg(err, "Failed updating file entry")
				}
			}
		}
	}

	return nil
}
