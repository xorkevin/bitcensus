package census

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"xorkevin.dev/hunter2/h2streamhash/blake2bstream"
	"xorkevin.dev/hunter2/h2streamhash/sha256stream"
	"xorkevin.dev/klog"
)

func TestCensus(t *testing.T) {
	t.Parallel()

	assert := require.New(t)

	rootDir := filepath.ToSlash(t.TempDir())

	dataDir := path.Join(rootDir, "bitcensus")
	storageDir := path.Join(rootDir, "storage")

	repoHelloFiles := map[string]string{
		"this/file/is/added.txt": `this file is added`,
	}
	otherFiles := map[string]string{
		"outside/dir/ignored": `this file is ignored`,
		"this/fails/regex":    `this file is ignored`,
	}

	addFile := func(name string, content string) {
		name = filepath.FromSlash(path.Join(storageDir, name))
		dir := filepath.Dir(name)
		assert.NoError(os.MkdirAll(dir, 0o777))
		assert.NoError(os.WriteFile(name, []byte(content), 0o666))
	}

	syncFiles := func() {
		for k, v := range repoHelloFiles {
			addFile(path.Join("hello", k), v)
		}
		for k, v := range otherFiles {
			addFile(path.Join("hello", k), v)
		}
	}

	syncFiles()

	census := New(klog.Discard{}, dataDir, SyncConfig{
		"hello": {
			Path: path.Join(storageDir, "hello"),
			Dirs: []RepoDirConfig{
				{
					Exact: false,
					Path:  "this",
					Match: `.txt$`,
				},
			},
		},
	})

	checkRepoExport := func(t *testing.T, prefix string) {
		t.Helper()

		prefix = "$" + prefix + "$"
		var b bytes.Buffer
		assert.NoError(census.ExportRepo(context.Background(), &b, "hello"))
		count := 0
		j := json.NewDecoder(&b)
		for j.More() {
			var entry FileEntry
			assert.NoError(j.Decode(&entry))
			count++
			assert.Contains(repoHelloFiles, entry.Name)
			content := repoHelloFiles[entry.Name]
			assert.Equal(int64(len(content)), entry.Size)
			assert.NotZero(entry.ModTime, entry)
			assert.NotZero(entry.Checksum, entry)
			assert.True(strings.HasPrefix(entry.Checksum, prefix), entry)
		}
		assert.Equal(len(repoHelloFiles), count)
	}

	{
		// sync and check export
		assert.NoError(census.SyncRepos(context.Background(), SyncFlags{}))
		checkRepoExport(t, blake2bstream.HashID)
		assert.NoError(census.VerifyRepos(context.Background(), VerifyFlags{}))
	}

	{
		// change file and verify should find checksum error
		repoHelloFiles["this/file/is/added.txt"] = `changed file 0`
		syncFiles()

		var err *ChecksumError
		assert.ErrorAs(census.VerifyRepos(context.Background(), VerifyFlags{}), &err)
		assert.Equal("hello", err.Repo)
		assert.Equal([]string{"this/file/is/added.txt"}, err.Mismatch)
	}

	{
		// a dry run will not modify the db
		assert.NoError(census.SyncRepos(context.Background(), SyncFlags{
			DryRun: true,
		}))
		var err *ChecksumError
		assert.ErrorAs(census.VerifyRepos(context.Background(), VerifyFlags{}), &err)
		assert.Equal("hello", err.Repo)
		assert.Equal([]string{"this/file/is/added.txt"}, err.Mismatch)
	}

	{
		// a re-sync should cause verify to pass again
		assert.NoError(census.SyncRepos(context.Background(), SyncFlags{}))
		checkRepoExport(t, blake2bstream.HashID)
		assert.NoError(census.VerifyRepos(context.Background(), VerifyFlags{}))
	}

	{
		// a re-sync should not change anything if no changes made
		assert.NoError(census.SyncRepos(context.Background(), SyncFlags{}))
		checkRepoExport(t, blake2bstream.HashID)
		assert.NoError(census.VerifyRepos(context.Background(), VerifyFlags{}))
	}

	{
		// simulate a bit flip
		name := filepath.FromSlash(path.Join(storageDir, "hello/this/file/is/added.txt"))
		info, err := os.Stat(name)
		assert.NoError(err)
		repoHelloFiles["this/file/is/added.txt"] = `changed file 1`
		syncFiles()
		assert.NoError(os.Chtimes(name, time.Now(), info.ModTime()))

		assert.NoError(census.SyncRepos(context.Background(), SyncFlags{}))
		checkRepoExport(t, blake2bstream.HashID)
		var cerr *ChecksumError
		assert.ErrorAs(census.VerifyRepos(context.Background(), VerifyFlags{}), &cerr)
		assert.Equal("hello", cerr.Repo)
		assert.Equal([]string{"this/file/is/added.txt"}, cerr.Mismatch)
	}

	{
		// force sync will avoid heuristic check
		assert.NoError(census.SyncRepos(context.Background(), SyncFlags{
			Force: true,
		}))
		checkRepoExport(t, blake2bstream.HashID)
		assert.NoError(census.VerifyRepos(context.Background(), VerifyFlags{}))
	}

	{
		// ensure compatibility with previous hash algs
		census = New(klog.Discard{}, dataDir, SyncConfig{
			"hello": {
				Path: path.Join(storageDir, "hello"),
				Dirs: []RepoDirConfig{
					{
						Exact: false,
						Path:  "this",
						Match: `.txt$`,
					},
				},
				HashAlg: sha256stream.HashID,
			},
		})

		assert.NoError(census.SyncRepos(context.Background(), SyncFlags{
			Force: true,
		}))
		checkRepoExport(t, blake2bstream.HashID)
		assert.NoError(census.VerifyRepos(context.Background(), VerifyFlags{}))
	}

	var dbExport bytes.Buffer
	assert.NoError(census.ExportRepo(context.Background(), &dbExport, "hello"))

	{
		// force verify will verify and update hash algs
		census = New(klog.Discard{}, dataDir, SyncConfig{
			"hello": {
				Path: path.Join(storageDir, "hello"),
				Dirs: []RepoDirConfig{
					{
						Exact: false,
						Path:  "this",
						Match: `.txt$`,
					},
				},
				HashAlg: sha256stream.HashID,
			},
		})

		assert.NoError(census.VerifyRepos(context.Background(), VerifyFlags{
			Upgrade: true,
		}))
		checkRepoExport(t, sha256stream.HashID)
	}

	{
		// import by default does not replace existing files
		dbImport := bytes.NewReader(dbExport.Bytes())
		assert.NoError(census.ImportRepo(context.Background(), dbImport, "hello", false))
		checkRepoExport(t, sha256stream.HashID)

		dbImport.Reset(dbExport.Bytes())

		assert.NoError(census.ImportRepo(context.Background(), dbImport, "hello", true))
		checkRepoExport(t, blake2bstream.HashID)
		assert.NoError(census.VerifyRepos(context.Background(), VerifyFlags{}))
	}

	{
		// files will only be removed with sync rm after
		name := filepath.FromSlash(path.Join(storageDir, "hello/this/file/is/added.txt"))
		assert.NoError(os.Remove(name))
		delete(repoHelloFiles, "this/file/is/added.txt")

		assert.NoError(census.SyncRepos(context.Background(), SyncFlags{}))
		assert.ErrorIs(census.VerifyRepos(context.Background(), VerifyFlags{}), ErrNotFound)

		assert.NoError(census.SyncRepos(context.Background(), SyncFlags{
			Prune: true,
		}))
		checkRepoExport(t, sha256stream.HashID)
		assert.NoError(census.VerifyRepos(context.Background(), VerifyFlags{}))
	}

	{
		// import handles file additions
		dbImport := bytes.NewReader(dbExport.Bytes())
		assert.NoError(census.ImportRepo(context.Background(), dbImport, "hello", false))
		assert.ErrorIs(census.VerifyRepos(context.Background(), VerifyFlags{}), ErrNotFound)
	}
}
