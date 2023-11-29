package census

import (
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"xorkevin.dev/bitcensus/dbsql"
	"xorkevin.dev/klog"
)

func TestCensus(t *testing.T) {
	t.Parallel()

	assert := require.New(t)

	rootDir := filepath.ToSlash(t.TempDir())

	dataDir := path.Join(rootDir, "bitcensus")
	testStateDBFile := path.Join(dataDir, "db", "teststate.db")
	assert.NoError(os.MkdirAll(filepath.Dir(filepath.FromSlash(testStateDBFile)), 0o777))
	rwDB := dbsql.NewSQLClient(klog.Discard{}, "file:"+filepath.FromSlash(testStateDBFile)+"?mode=rwc")
	assert.NoError(rwDB.Init())
	rdb := dbsql.NewSQLClient(klog.Discard{}, "file:"+filepath.FromSlash(testStateDBFile)+"?mode=ro")
	assert.NoError(rdb.Init())
}
