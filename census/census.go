package census

import (
	"context"
	"encoding/base64"
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
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"
	"xorkevin.dev/bitcensus/census/censusdbmodel"
	"xorkevin.dev/bitcensus/dbsql"
	"xorkevin.dev/bitcensus/parity"
	"xorkevin.dev/bitcensus/util/bytefmt"
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
		log     *klog.LevelLogger
		dataDir string
		cfg     SyncConfig
	}

	RepoDirConfig struct {
		Exact bool   `mapstructure:"exact"`
		Path  string `mapstructure:"path"`
		Match string `mapstructure:"match"`
	}

	RepoConfig struct {
		Path   string          `mapstructure:"path"`
		Dirs   []RepoDirConfig `mapstructure:"dirs"`
		Parity ParityConfig    `mapstructure:"parity"`
	}

	ParityConfig struct {
		Dir          string `mapstructure:"dir"`
		BlockSize    uint64 `mapstructure:"blocksize"`
		Shards       uint64 `mapstructure:"shards"`
		ParityShards uint64 `mapstructure:"parityshards"`
	}

	SyncConfig map[string]RepoConfig

	SyncFlags struct {
		Prune    bool
		Update   bool
		Checksum bool
		DryRun   bool
	}

	VerifyFlags struct {
		Before time.Time
		Repair bool
	}

	parityOpts struct {
		Dir          fs.FS
		BlockSize    uint64
		Shards       uint64
		ParityShards uint64
	}
)

func New(log klog.Logger, dataDir string, cfg SyncConfig) *Census {
	return &Census{
		log:     klog.NewLevelLogger(log),
		dataDir: dataDir,
		cfg:     cfg,
	}
}

func (c *Census) getFilesRepo(name string, mode string) (censusdbmodel.Repo, *dbsql.SQLClient, error) {
	// url must be in the form of
	// file:rel/path/to/file.db?optquery=value&otheroptquery=value
	dir := path.Join(c.dataDir, "db")
	u := path.Join(dir, name+".db")
	q := url.Values{}
	q.Set("mode", mode)
	q.Set("_busy_timeout", "5000")
	q.Set("_journal_mode", "WAL")
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

	files, d, err := c.getFilesRepo(name, "rwc")
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
	var par *parityOpts
	if cfg.Parity.Dir != "" {
		par = &parityOpts{
			Dir:          kfs.DirFS(cfg.Parity.Dir),
			BlockSize:    cfg.Parity.BlockSize,
			Shards:       cfg.Parity.Shards,
			ParityShards: cfg.Parity.ParityShards,
		}
	}

	for _, i := range cfg.Dirs {
		p := path.Clean(i.Path)
		if i.Exact {
			c.log.Debug(ctx, "Adding repo file",
				klog.AString("repopath", cfg.Path),
				klog.AString("repofilepath", p),
			)
			if err := c.syncRepoFileFS(ctx, files, rootDir, par, p, flags); err != nil {
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
			if err := c.syncRepoDir(ctx, files, rootDir, par, r, p, fs.FileInfoToDirEntry(info), flags); err != nil {
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

func (c *Census) syncRepoDir(ctx context.Context, files censusdbmodel.Repo, dir fs.FS, par *parityOpts, match *regexp.Regexp, p string, entry fs.DirEntry, flags SyncFlags) error {
	if !entry.IsDir() {
		if !match.MatchString(p) {
			c.log.Debug(ctx, "Skipping unmatched file",
				klog.AString("path", p),
			)
			return nil
		}

		if err := c.syncRepoFileFS(ctx, files, dir, par, p, flags); err != nil {
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
		if err := c.syncRepoDir(ctx, files, dir, par, match, path.Join(p, i.Name()), i, flags); err != nil {
			return err
		}
	}
	return nil
}

func (c *Census) syncRepoFileFS(ctx context.Context, files censusdbmodel.Repo, dir fs.FS, par *parityOpts, p string, flags SyncFlags) error {
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

	missingParityHash := false
	missingParityFile := false
	sizeDiffers := false
	if existingEntry != nil {
		if par != nil {
			missingParityHash = existingEntry.ParityHash == "" || existingEntry.HeaderHash == ""
			if _, err := fs.Stat(par.Dir, p+parExt); err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					return kerrors.WithMsg(err, "Failed to stat file")
				}
				missingParityFile = true
			}
		}
		sizeDiffers = info.Size() != existingEntry.Size
	}

	if !flags.Checksum {
		if !missingParityHash && !missingParityFile && !sizeDiffers && existingEntry != nil && info.ModTime().Equal(time.Unix(0, existingEntry.ModTime)) {
			c.log.Debug(ctx, "Skipping unchanged file on matching size and modtime",
				klog.AString("path", p),
			)
			return nil
		}
	}

	c.log.Info(ctx, "Syncing file",
		klog.AString("path", p),
		klog.AString("size", bytefmt.ToString(float64(info.Size()))),
	)
	if flags.DryRun {
		return nil
	}

	if existingEntry == nil {
		// handle addition of new entry
		var h, ph, hh string
		if par != nil {
			var err error
			start := time.Now()
			h, ph, hh, err = c.writeParityFile(dir, *par, p, "")
			duration := time.Since(start)
			if err != nil {
				return kerrors.WithMsg(err, "Failed hashing and writing parity file")
			}
			c.log.Info(ctx, "Hashed file and gen parity",
				klog.AString("path", p),
				klog.AString("size", bytefmt.ToString(float64(info.Size()))),
				klog.ADuration("duration", duration),
			)
		} else {
			var err error
			start := time.Now()
			h, err = c.hashFile(dir, p)
			duration := time.Since(start)
			if err != nil {
				return kerrors.WithMsg(err, "Failed to hash file")
			}
			c.log.Info(ctx, "Hashed file",
				klog.AString("path", p),
				klog.AString("size", bytefmt.ToString(float64(info.Size()))),
				klog.AString("hashrate", humanHashRate(info.Size(), duration)),
			)
		}

		m := files.New(p, info.Size(), info.ModTime().UnixNano(), h, ph, hh)
		if err := files.Insert(ctx, m); err != nil {
			return kerrors.WithMsg(err, "Failed adding file entry")
		}
		c.log.Info(ctx, "Added file",
			klog.AString("path", p),
			klog.AString("size", bytefmt.ToString(float64(info.Size()))),
		)
		return nil
	}

	if sizeDiffers && !flags.Update {
		// early return for differing size
		c.log.Warn(ctx, "Size mismatch",
			klog.AString("path", p),
			klog.AString("size", bytefmt.ToString(float64(info.Size()))),
		)
		return nil
	}

	if par == nil {
		// handle no parity config
		start := time.Now()
		h, err := c.hashFile(dir, p)
		duration := time.Since(start)
		if err != nil {
			return kerrors.WithMsg(err, "Failed to hash file")
		}
		mismatch := h != existingEntry.Hash
		if mismatch && !flags.Update {
			c.log.Warn(ctx, "Checksum mismatch",
				klog.AString("path", p),
				klog.AString("size", bytefmt.ToString(float64(info.Size()))),
				klog.AString("hashrate", humanHashRate(info.Size(), duration)),
			)
			return nil
		}
		m := files.New(p, info.Size(), info.ModTime().UnixNano(), h, "", "")
		if err := files.Update(ctx, m); err != nil {
			return kerrors.WithMsg(err, "Failed updating file entry")
		}
		if mismatch {
			c.log.Info(ctx, "Updated changed file",
				klog.AString("path", p),
				klog.AString("size", bytefmt.ToString(float64(info.Size()))),
				klog.AString("hashrate", humanHashRate(info.Size(), duration)),
			)
		} else {
			c.log.Info(ctx, "Verified file",
				klog.AString("path", p),
				klog.AString("size", bytefmt.ToString(float64(info.Size()))),
				klog.AString("hashrate", humanHashRate(info.Size(), duration)),
			)
		}
		return nil
	}

	if !missingParityHash && !missingParityFile && !sizeDiffers {
		// handle existing parity file
		start := time.Now()
		h, err := c.hashFile(dir, p)
		duration := time.Since(start)
		if err != nil {
			return kerrors.WithMsg(err, "Failed to hash file")
		}
		if h == existingEntry.Hash {
			c.log.Info(ctx, "Verified file",
				klog.AString("path", p),
				klog.AString("size", bytefmt.ToString(float64(info.Size()))),
				klog.AString("hashrate", humanHashRate(info.Size(), duration)),
			)

			// if no mismatch, also check parity file
			start := time.Now()
			ph, err := c.hashFile(par.Dir, p+parExt)
			duration := time.Since(start)
			if err != nil {
				return kerrors.WithMsg(err, "Failed to hash parity file")
			}
			if ph == existingEntry.ParityHash {
				// handle parity file match
				m := files.New(p, info.Size(), info.ModTime().UnixNano(), h, ph, existingEntry.HeaderHash)
				if err := files.Update(ctx, m); err != nil {
					return kerrors.WithMsg(err, "Failed updating file entry")
				}
				c.log.Info(ctx, "Verified parity",
					klog.AString("path", p),
					klog.ADuration("duration", duration),
				)
				return nil
			}
			c.log.Warn(ctx, "Parity checksum mismatch",
				klog.AString("path", p),
				klog.ADuration("duration", duration),
			)

			// handle parity file mismatch
			start = time.Now()
			h, ph, hh, err := c.writeParityFile(dir, *par, p, existingEntry.Hash)
			duration = time.Since(start)
			if err != nil {
				if errors.Is(err, parity.ErrFileNoMatch) {
					return kerrors.WithMsg(nil, "File changed during reading")
				}
				return kerrors.WithMsg(err, "Failed hashing and writing parity file")
			}
			m := files.New(p, info.Size(), info.ModTime().UnixNano(), h, ph, hh)
			if err := files.Update(ctx, m); err != nil {
				return kerrors.WithMsg(err, "Failed updating file entry")
			}
			c.log.Info(ctx, "Verified file and gen parity",
				klog.AString("path", p),
				klog.AString("size", bytefmt.ToString(float64(info.Size()))),
				klog.ADuration("duration", duration),
			)
			return nil
		}

		// handle file mismatch
		c.log.Warn(ctx, "Checksum mismatch",
			klog.AString("path", p),
			klog.AString("size", bytefmt.ToString(float64(info.Size()))),
			klog.AString("hashrate", humanHashRate(info.Size(), duration)),
		)
		if !flags.Update {
			return nil
		}
	}

	// this branch is reached by having an existing file, a parity config and one
	// of the following
	//
	// - missing parity hash data
	// - missing a parity file
	// - having a file mismatch in update mode
	//
	// in all cases, it is safe to regenerate the parity file

	matchFileHash := existingEntry.Hash
	if flags.Update {
		matchFileHash = ""
	}
	start := time.Now()
	h, ph, hh, err := c.writeParityFile(dir, *par, p, matchFileHash)
	duration := time.Since(start)
	if err != nil {
		if errors.Is(err, parity.ErrFileNoMatch) {
			c.log.Warn(ctx, "Checksum mismatch",
				klog.AString("path", p),
				klog.AString("size", bytefmt.ToString(float64(info.Size()))),
				klog.AString("hashrate", humanHashRate(info.Size(), duration)),
			)
			return nil
		}
		return kerrors.WithMsg(err, "Failed hashing and writing parity file")
	}
	m := files.New(p, info.Size(), info.ModTime().UnixNano(), h, ph, hh)
	if err := files.Update(ctx, m); err != nil {
		return kerrors.WithMsg(err, "Failed updating file entry")
	}
	if h != existingEntry.Hash {
		c.log.Info(ctx, "Updated changed file and gen parity",
			klog.AString("path", p),
			klog.AString("size", bytefmt.ToString(float64(info.Size()))),
			klog.ADuration("duration", duration),
		)
	} else {
		c.log.Info(ctx, "Verified file and gen parity",
			klog.AString("path", p),
			klog.AString("size", bytefmt.ToString(float64(info.Size()))),
			klog.ADuration("duration", duration),
		)
	}

	return nil
}

func humanHashRate(size int64, duration time.Duration) string {
	return bytefmt.ToString(float64(size)/duration.Seconds()) + "/s"
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

	files, d, err := c.getFilesRepo(name, "rw")
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
	var par *parityOpts
	if cfg.Parity.Dir != "" {
		par = &parityOpts{
			Dir:          kfs.DirFS(cfg.Parity.Dir),
			BlockSize:    cfg.Parity.BlockSize,
			Shards:       cfg.Parity.Shards,
			ParityShards: cfg.Parity.ParityShards,
		}
	}

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
			match, err := c.verifyRepoFileFS(ctx, files, rootDir, par, i, flags)
			if err != nil {
				return kerrors.WithMsg(err, fmt.Sprintf("Failed to verify file %s", i.Name))
			}
			if !match {
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

func (c *Census) verifyRepoFileFS(ctx context.Context, files censusdbmodel.Repo, dir fs.FS, par *parityOpts, entry censusdbmodel.Model, flags VerifyFlags) (bool, error) {
	if !flags.Before.IsZero() && !time.UnixMilli(entry.LastVerifiedAt).Before(flags.Before) {
		c.log.Debug(ctx, "Skipping recently verified file", klog.AString("path", entry.Name))
		return true, nil
	}

	info, err := fs.Stat(dir, entry.Name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, kerrors.WithKind(err, ErrNotFound, "File does not exist")
		}
		return false, kerrors.WithMsg(err, "Failed to stat file")
	}

	c.log.Info(ctx, "Verifying file",
		klog.AString("path", entry.Name),
		klog.AString("size", bytefmt.ToString(float64(info.Size()))),
	)

	start := time.Now()
	match, err := c.verifyFile(dir, entry.Name, entry.Hash)
	if err != nil {
		return false, kerrors.WithMsg(err, "Failed to verify file")
	}
	duration := time.Since(start)
	if match {
		if par == nil || entry.ParityHash == "" {
			if err := files.Update(ctx, files.New(entry.Name, info.Size(), info.ModTime().UnixNano(), entry.Hash, entry.ParityHash, entry.HeaderHash)); err != nil {
				return false, kerrors.WithMsg(err, "Failed updating file entry")
			}
			c.log.Info(ctx, "Verified file",
				klog.AString("path", entry.Name),
				klog.AString("size", bytefmt.ToString(float64(info.Size()))),
				klog.AString("hashrate", humanHashRate(info.Size(), duration)),
			)
			return true, nil
		}

		c.log.Info(ctx, "Verified file",
			klog.AString("path", entry.Name),
			klog.AString("size", bytefmt.ToString(float64(info.Size()))),
			klog.AString("hashrate", humanHashRate(info.Size(), duration)),
		)

		start := time.Now()
		parityMatch, err := c.verifyFile(par.Dir, entry.Name+parExt, entry.ParityHash)
		duration := time.Since(start)
		if err != nil {
			return false, kerrors.WithMsg(err, "Failed to hash parity file")
		}
		if parityMatch {
			if err := files.Update(ctx, files.New(entry.Name, info.Size(), info.ModTime().UnixNano(), entry.Hash, entry.ParityHash, entry.HeaderHash)); err != nil {
				return false, kerrors.WithMsg(err, "Failed updating file entry")
			}
			c.log.Info(ctx, "Verified parity",
				klog.AString("path", entry.Name),
				klog.ADuration("duration", duration),
			)
			return true, nil
		}
		c.log.Warn(ctx, "Parity checksum mismatch",
			klog.AString("path", entry.Name),
			klog.ADuration("duration", duration),
		)
	} else {
		c.log.Warn(ctx, "Checksum mismatch",
			klog.AString("path", entry.Name),
			klog.AString("size", bytefmt.ToString(float64(info.Size()))),
			klog.AString("hashrate", humanHashRate(info.Size(), duration)),
		)
	}

	if par != nil && entry.ParityHash != "" && flags.Repair {
		// TODO repair file
	}

	return false, nil
}

func (c *Census) verifyFile(dir fs.FS, name string, sum string) (_ bool, retErr error) {
	h, err := c.hashFile(dir, name)
	if err != nil {
		return false, err
	}
	return h == sum, nil
}

func (c *Census) hashFile(dir fs.FS, name string) (_ string, retErr error) {
	h, err := blake2b.New512(nil)
	if err != nil {
		return "", kerrors.WithMsg(err, "Failed creating hash")
	}
	if err := c.readFile(h, dir, name); err != nil {
		return "", err
	}
	return hashBytesToStr(h.Sum(nil)), nil
}

const (
	hashPrefix = "$b2b$"
	parExt     = ".bcp"
)

func hashBytesToStr(b []byte) string {
	return hashPrefix + base64.RawURLEncoding.EncodeToString(b)
}

func parseHashStrToBytes(s string) ([]byte, error) {
	s, ok := strings.CutPrefix(s, hashPrefix)
	if !ok {
		return nil, kerrors.WithMsg(nil, "Malformed hash")
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, kerrors.WithMsg(err, "Malformed hash")
	}
	return b, nil
}

func (c *Census) readFile(dest io.Writer, dir fs.FS, name string) (retErr error) {
	var buf [1024 * 1024]byte
	f, err := dir.Open(name)
	if err != nil {
		return kerrors.WithMsg(err, "Failed opening file")
	}
	defer func() {
		if err := f.Close(); err != nil {
			retErr = errors.Join(retErr, kerrors.WithMsg(err, "Failed to close file"))
		}
	}()
	if _, err := io.CopyBuffer(dest, f, buf[:]); err != nil {
		return kerrors.WithMsg(err, "Failed reading file")
	}
	return nil
}

func (c *Census) writeParityFile(dir fs.FS, par parityOpts, name string, matchFileHash string) (_, _, _ string, retErr error) {
	var matchFileHashBytes parity.Hash
	if b, err := parseHashStrToBytes(matchFileHash); err != nil {
		return "", "", "", err
	} else {
		if copy(matchFileHashBytes[:], b) != parity.HeaderHashSize {
			return "", "", "", kerrors.WithMsg(nil, "Malformed hash")
		}
	}
	dataFile, err := dir.Open(name)
	if err != nil {
		return "", "", "", kerrors.WithMsg(err, "Failed opening file")
	}
	defer func() {
		if err := dataFile.Close(); err != nil {
			retErr = errors.Join(retErr, kerrors.WithMsg(err, "Failed to close file"))
		}
	}()
	data, ok := dataFile.(io.ReadSeeker)
	if !ok {
		return "", "", "", kerrors.WithMsg(nil, "Data file is not seekable")
	}
	parityFile, err := kfs.OpenFile(par.Dir, name+parExt, os.O_RDWR|os.O_CREATE, 0o666)
	if err != nil {
		return "", "", "", kerrors.WithMsg(err, "Failed opening parity file")
	}
	defer func() {
		if err := parityFile.Close(); err != nil {
			retErr = errors.Join(retErr, kerrors.WithMsg(err, "Failed to close parity file"))
		}
	}()
	parFile, ok := parityFile.(parity.ReadWriteSeekTruncater)
	if !ok {
		return "", "", "", kerrors.WithMsg(nil, "Parity file is not truncatable")
	}
	fileHash, headerHash, err := parity.WriteParityFile(parFile, data, parity.ShardConfig{
		BlockSize:        par.BlockSize,
		ShardCount:       par.Shards,
		ParityShardCount: par.ParityShards,
	}, matchFileHashBytes)
	if err != nil {
		return "", "", "", kerrors.WithMsg(err, "Failed computing parity file")
	}
	if _, err := parFile.Seek(0, io.SeekStart); err != nil {
		return "", "", "", kerrors.WithMsg(err, "Failed seeking parity file")
	}
	h, err := blake2b.New512(nil)
	if err != nil {
		return "", "", "", kerrors.WithMsg(err, "Failed creating hash")
	}
	var buf [1024 * 1024]byte
	if _, err := io.CopyBuffer(h, parFile, buf[:]); err != nil {
		return "", "", "", kerrors.WithMsg(err, "Failed reading parity file")
	}
	return hashBytesToStr(fileHash[:]), hashBytesToStr(h.Sum(nil)), hashBytesToStr(headerHash[:]), nil
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

	files, d, err := c.getFilesRepo(name, "ro")
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

	files, d, err := c.getFilesRepo(name, "rwc")
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
			// parity is a local concept
			m = files.New(entry.Name, entry.Size, entry.ModTime, entry.Checksum, "", "")
			m.LastVerifiedAt = 0
			if err := files.Insert(ctx, m); err != nil {
				return kerrors.WithMsg(err, "Failed adding file entry")
			}
		} else if entry.Checksum != m.Hash && override {
			m.Size = entry.Size
			m.ModTime = entry.ModTime
			m.Hash = entry.Checksum
			// discard parity if checksum differs
			m.ParityHash = ""
			m.HeaderHash = ""
			m.LastVerifiedAt = 0
			if err := files.Update(ctx, m); err != nil {
				return kerrors.WithMsg(err, "Failed updating file entry")
			}
		}
	}

	return nil
}
