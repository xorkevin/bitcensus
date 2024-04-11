package census

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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

	checkRepoExport := func(t *testing.T) {
		t.Helper()

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
			assert.True(strings.HasPrefix(entry.Checksum, hashPrefix), entry)
		}
		assert.Equal(len(repoHelloFiles), count)
	}

	{
		// sync and check export
		assert.NoError(census.SyncRepos(context.Background(), SyncFlags{}))
		checkRepoExport(t)
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
			Update: true,
		}))
		var err *ChecksumError
		assert.ErrorAs(census.VerifyRepos(context.Background(), VerifyFlags{}), &err)
		assert.Equal("hello", err.Repo)
		assert.Equal([]string{"this/file/is/added.txt"}, err.Mismatch)
	}

	{
		// a sync will not update existing files
		assert.NoError(census.SyncRepos(context.Background(), SyncFlags{}))
		var err *ChecksumError
		assert.ErrorAs(census.VerifyRepos(context.Background(), VerifyFlags{}), &err)
		assert.Equal("hello", err.Repo)
		assert.Equal([]string{"this/file/is/added.txt"}, err.Mismatch)
	}

	{
		// an update sync should cause verify to pass again
		assert.NoError(census.SyncRepos(context.Background(), SyncFlags{
			Update: true,
		}))
		checkRepoExport(t)
		assert.NoError(census.VerifyRepos(context.Background(), VerifyFlags{}))
	}

	{
		// a re-sync should not change anything if no changes made
		assert.NoError(census.SyncRepos(context.Background(), SyncFlags{}))
		checkRepoExport(t)
		assert.NoError(census.VerifyRepos(context.Background(), VerifyFlags{}))
	}

	var dbExport bytes.Buffer
	assert.NoError(census.ExportRepo(context.Background(), &dbExport, "hello"))

	{
		// simulate a bit flip
		name := filepath.FromSlash(path.Join(storageDir, "hello/this/file/is/added.txt"))
		info, err := os.Stat(name)
		assert.NoError(err)
		repoHelloFiles["this/file/is/added.txt"] = `changed file 1`
		syncFiles()
		assert.NoError(os.Chtimes(name, time.Now(), info.ModTime()))

		assert.NoError(census.SyncRepos(context.Background(), SyncFlags{}))
		checkRepoExport(t)
		var cerr *ChecksumError
		assert.ErrorAs(census.VerifyRepos(context.Background(), VerifyFlags{}), &cerr)
		assert.Equal("hello", cerr.Repo)
		assert.Equal([]string{"this/file/is/added.txt"}, cerr.Mismatch)
	}

	{
		// checksum sync will avoid heuristic check
		assert.NoError(census.SyncRepos(context.Background(), SyncFlags{
			Update:   true,
			Checksum: true,
		}))
		checkRepoExport(t)
		assert.NoError(census.VerifyRepos(context.Background(), VerifyFlags{}))
	}

	{
		// import by default does not replace existing files
		dbImport := bytes.NewReader(dbExport.Bytes())
		assert.NoError(census.ImportRepo(context.Background(), dbImport, "hello", false))
		checkRepoExport(t)

		dbImport.Reset(dbExport.Bytes())

		assert.NoError(census.ImportRepo(context.Background(), dbImport, "hello", true))
		checkRepoExport(t)
		var cerr *ChecksumError
		assert.ErrorAs(census.VerifyRepos(context.Background(), VerifyFlags{}), &cerr)
		assert.Equal("hello", cerr.Repo)
		assert.Equal([]string{"this/file/is/added.txt"}, cerr.Mismatch)
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
		checkRepoExport(t)
		assert.NoError(census.VerifyRepos(context.Background(), VerifyFlags{}))
	}

	{
		// import handles file additions
		dbImport := bytes.NewReader(dbExport.Bytes())
		assert.NoError(census.ImportRepo(context.Background(), dbImport, "hello", false))
		assert.ErrorIs(census.VerifyRepos(context.Background(), VerifyFlags{}), ErrNotFound)
	}
}

func TestParity(t *testing.T) {
	t.Parallel()

	assert := require.New(t)

	rootDir := filepath.ToSlash(t.TempDir())

	dataDir := path.Join(rootDir, "bitcensus")
	storageDir := path.Join(rootDir, "storage")
	parityDir := path.Join(rootDir, "parity")

	repoHelloFiles := map[string]string{
		"file.txt": `this file is added`,
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
	}

	syncFiles()

	census := New(klog.New(klog.OptHandler(klog.NewTextSlogHandler(os.Stderr))), dataDir, SyncConfig{
		"hello": {
			Path: path.Join(storageDir, "hello"),
			Dirs: []RepoDirConfig{
				{
					Exact: false,
					Path:  "",
				},
			},
			Parity: ParityConfig{
				Dir:          parityDir,
				BlockSize:    1024,
				Shards:       6,
				ParityShards: 3,
			},
		},
	})

	checkRepoExport := func(t *testing.T) {
		t.Helper()

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
			assert.True(strings.HasPrefix(entry.Checksum, hashPrefix), entry)
		}
		assert.Equal(len(repoHelloFiles), count)
	}

	parityFileName := filepath.FromSlash(path.Join(parityDir, "file.txt.bcp"))

	{
		// sync and check export
		assert.NoError(census.SyncRepos(context.Background(), SyncFlags{}))
		checkRepoExport(t)
		assert.NoError(census.VerifyRepos(context.Background(), VerifyFlags{}))
		// check parity file exists
		info, err := os.Stat(parityFileName)
		assert.NoError(err)
		assert.NotZero(info.Size())

		// additional sync will not change parity file mod time
		assert.NoError(census.SyncRepos(context.Background(), SyncFlags{
			Checksum: true,
		}))
		checkRepoExport(t)
		assert.NoError(census.VerifyRepos(context.Background(), VerifyFlags{}))

		info2, err := os.Stat(parityFileName)
		assert.NoError(err)
		assert.Equal(info.ModTime(), info2.ModTime())
	}

	{
		// check that parity file is repaired on sync
		parityFile, err := os.ReadFile(parityFileName)
		assert.NoError(err)

		{
			// simulate corrupt parity file
			b := slices.Clone(parityFile)
			b[0] = 0
			b[1] = 0
			b[2] = 0
			b[3] = 0
			assert.NoError(os.WriteFile(parityFileName, b, 0o666))
		}

		// parity file change is detected
		var cerr *ChecksumError
		assert.ErrorAs(census.VerifyRepos(context.Background(), VerifyFlags{}), &cerr)
		assert.Equal("hello", cerr.Repo)
		assert.Equal([]string{"file.txt"}, cerr.Mismatch)

		assert.NoError(census.SyncRepos(context.Background(), SyncFlags{
			Checksum: true,
		}))
		checkRepoExport(t)
		assert.NoError(census.VerifyRepos(context.Background(), VerifyFlags{}))

		// check that parity file is repaired
		parityFile2, err := os.ReadFile(parityFileName)
		assert.NoError(err)
		assert.Equal(parityFile, parityFile2)
	}

	{
		// update both hash and parity on file change
		parityFile, err := os.ReadFile(parityFileName)
		assert.NoError(err)

		repoHelloFiles["file.txt"] = `changed file 0`
		syncFiles()

		assert.NoError(census.SyncRepos(context.Background(), SyncFlags{}))
		var cerr *ChecksumError
		assert.ErrorAs(census.VerifyRepos(context.Background(), VerifyFlags{}), &cerr)
		assert.Equal("hello", cerr.Repo)
		assert.Equal([]string{"file.txt"}, cerr.Mismatch)

		{
			parityFile2, err := os.ReadFile(parityFileName)
			assert.NoError(err)
			assert.Equal(parityFile, parityFile2)
		}

		assert.NoError(census.SyncRepos(context.Background(), SyncFlags{
			Update: true,
		}))
		checkRepoExport(t)
		assert.NoError(census.VerifyRepos(context.Background(), VerifyFlags{}))

		{
			parityFile3, err := os.ReadFile(parityFileName)
			assert.NoError(err)
			assert.NotEqual(parityFile, parityFile3)
		}
	}

	{
		// repair both file and parity
		parityFile, err := os.ReadFile(parityFileName)
		assert.NoError(err)

		repoHelloFiles["file.txt"] = `changed file 1`
		syncFiles()

		assert.NoError(census.VerifyRepos(context.Background(), VerifyFlags{
			Repair: true,
		}))
		assert.NoError(census.VerifyRepos(context.Background(), VerifyFlags{}))

		{
			parityFile2, err := os.ReadFile(parityFileName)
			assert.NoError(err)
			assert.Equal(parityFile, parityFile2)
		}

		{
			// simulate corrupt parity file
			b := slices.Clone(parityFile)
			b[0] = 0
			b[1] = 0
			b[2] = 0
			b[3] = 0
			assert.NoError(os.WriteFile(parityFileName, b, 0o666))
		}

		assert.NoError(census.VerifyRepos(context.Background(), VerifyFlags{
			Repair: true,
		}))
		assert.NoError(census.VerifyRepos(context.Background(), VerifyFlags{}))

		{
			parityFile3, err := os.ReadFile(parityFileName)
			assert.NoError(err)
			assert.Equal(parityFile, parityFile3)
		}
	}
}
