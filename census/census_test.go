package census

import (
	"bytes"
	"context"
	"encoding/json"
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

	repoHelloFiles := map[string]string{
		"this/file/is/added.txt": `this file is added`,
	}
	otherFiles := map[string]string{
		"ignored_file": `this file is ignored`,
	}

	addFile := func(name string, content string) {
		name = filepath.FromSlash(path.Join(storageDir, name))
		dir := filepath.Dir(name)
		assert.NoError(os.MkdirAll(dir, 0o777))
		assert.NoError(os.WriteFile(name, []byte(content), 0o644))
	}
	for k, v := range repoHelloFiles {
		addFile(path.Join("hello", k), v)
	}
	for k, v := range otherFiles {
		addFile(path.Join("hello", k), v)
	}

	census := NewCensus(klog.Discard{}, dataDir, SyncConfig{
		Repos: map[string]RepoConfig{
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
			assert.Contains(repoHelloFiles, entry.Name)
			content := repoHelloFiles[entry.Name]
			assert.Equal(int64(len(content)), entry.Size)
			assert.NotZero(entry.ModTime)
			assert.NotZero(entry.Checksum)
		}
		assert.Equal(len(repoHelloFiles), count)
	}
}
