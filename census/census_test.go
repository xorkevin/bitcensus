package census

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"xorkevin.dev/klog"
)

func TestCensus(t *testing.T) {
	t.Parallel()

	assert := require.New(t)

	rootDir := filepath.ToSlash(t.TempDir())

	dataDir := path.Join(rootDir, "bitcensus")
	storageDir := path.Join(rootDir, "storage")

	storedFiles := map[string]string{
		"ignored_file":           `this file is ignored`,
		"this/file/is/added.txt": `this file is added`,
	}
	{
		var filemode fs.FileMode = 0o644
		for k, v := range storedFiles {
			name := filepath.FromSlash(path.Join(storageDir, k))
			dir := filepath.Dir(name)
			assert.NoError(os.MkdirAll(dir, 0o777))
			assert.NoError(os.WriteFile(name, []byte(v), filemode))
		}
	}

	census := NewCensus(klog.Discard{}, dataDir, SyncConfig{
		Repos: map[string]RepoConfig{
			"hello": {
				Path: path.Join(storageDir, "hello"),
				Dirs: []RepoDirConfig{
					{
						Exact: false,
						Path:  "abc",
						Match: `.txt$`,
					},
				},
			},
		},
	})

	t.Log(rootDir)

	assert.NoError(census.SyncRepos(context.Background(), SyncFlags{}))

	{
		var b bytes.Buffer
		census.ExportRepo(context.Background(), &b, "hello")
		count := 0
		j := json.NewDecoder(&b)
		for j.More() {
			var entry FileEntry
			assert.NoError(j.Decode(&entry))
			count++
			assert.Contains(storedFiles, entry.Name)
			content := storedFiles[entry.Name]
			assert.Equal(len(content), entry.Size)
			assert.NotZero(entry.ModTime)
			assert.NotZero(entry.Checksum)
		}
		assert.Equal(len(storedFiles), count)
	}
}
