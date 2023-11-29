package cmd

import (
	"context"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"xorkevin.dev/bitcensus/dbsql"
	"xorkevin.dev/hunter2/h2streamhash"
	"xorkevin.dev/hunter2/h2streamhash/blake2bstream"
	"xorkevin.dev/kerrors"
	"xorkevin.dev/kfs"
	"xorkevin.dev/klog"
)

type (
	Cmd struct {
		rootCmd   *cobra.Command
		log       *klog.LevelLogger
		version   string
		rootFlags rootFlags
		docFlags  docFlags
	}

	rootFlags struct {
		cfgFile    string
		stateDBDir string
		logLevel   string
		logJSON    bool
	}
)

func New() *Cmd {
	return &Cmd{}
}

func (c *Cmd) Execute() {
	buildinfo := ReadVCSBuildInfo()
	c.version = buildinfo.ModVersion
	rootCmd := &cobra.Command{
		Use:               "bitcensus",
		Short:             "A file system census utility",
		Long:              `A file system census utility`,
		Version:           c.version,
		PersistentPreRun:  c.initConfig,
		DisableAutoGenTag: true,
	}
	rootCmd.PersistentFlags().StringVar(&c.rootFlags.cfgFile, "config", "", "config file (default is $XDG_CONFIG_HOME/bitcensus.json)")
	rootCmd.PersistentFlags().StringVar(&c.rootFlags.stateDBDir, "state-db-dir", "", "state db directory (default is $XDG_DATA_HOME/bitcensus)")
	rootCmd.PersistentFlags().StringVar(&c.rootFlags.logLevel, "log-level", "info", "log level")
	rootCmd.PersistentFlags().BoolVar(&c.rootFlags.logJSON, "log-json", false, "output json logs")

	viper.SetDefault("statedbdir", getXDGDataDir())

	c.rootCmd = rootCmd

	rootCmd.AddCommand(c.getDocCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
		return
	}
}

func (c *Cmd) getStateDBDir() (fs.FS, string) {
	dbdir := c.rootFlags.stateDBDir
	if dbdir == "" {
		dbdir = viper.GetString("statedbdir")
		if dbdir == "" {
			dbdir = "."
		}
	}
	return kfs.DirFS(dbdir), dbdir
}

func (c *Cmd) createHasherVerifier() (map[string]h2streamhash.Hasher, *h2streamhash.Verifier) {
	hasher := blake2bstream.NewHasher(blake2bstream.Config{})
	algs := map[string]h2streamhash.Hasher{
		hasher.ID(): hasher,
	}
	verifier := h2streamhash.NewVerifier()
	verifier.Register(hasher)
	return algs, verifier
}

func (c *Cmd) getStateDB(name string, mode string) (any, error) {
	_, dataDir := c.getStateDBDir()

	// url must be in the form of
	// file:rel/path/to/file.db?optquery=value&otheroptquery=value
	u := url.URL{
		Scheme: "file",
		Opaque: path.Join(dataDir, "db", name+".db"),
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

	return nil, nil
}

// initConfig reads in config file and ENV variables if set.
func (c *Cmd) initConfig(cmd *cobra.Command, args []string) {
	logWriter := klog.NewSyncWriter(os.Stderr)
	var handler *klog.SlogHandler
	if c.rootFlags.logJSON {
		handler = klog.NewJSONSlogHandler(logWriter)
	} else {
		handler = klog.NewTextSlogHandler(logWriter)
		handler.FieldTimeInfo = ""
		handler.FieldCaller = ""
		handler.FieldMod = ""
	}
	c.log = klog.NewLevelLogger(klog.New(
		klog.OptHandler(handler),
		klog.OptMinLevelStr(c.rootFlags.logLevel),
	))

	if c.rootFlags.cfgFile != "" {
		viper.SetConfigFile(c.rootFlags.cfgFile)
	} else {
		viper.SetConfigName("bitcensus")
		viper.AddConfigPath(".")

		// Search config in $XDG_CONFIG_HOME/bitcensus directory
		if cfgdir, err := os.UserConfigDir(); err != nil {
			c.log.WarnErr(context.Background(), kerrors.WithMsg(err, "Failed reading user config dir"))
		} else {
			viper.AddConfigPath(filepath.Join(cfgdir, "bitcensus"))
		}
	}

	viper.SetEnvPrefix("BITCENSUS")
	viper.AutomaticEnv() // read in environment variables that match
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "__"))

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err != nil {
		c.log.Debug(context.Background(), "Failed reading config", klog.AString("err", err.Error()))
	} else {
		c.log.Debug(context.Background(), "Using config", klog.AString("file", viper.ConfigFileUsed()))
	}
}

func (c *Cmd) logFatal(err error) {
	c.log.Err(context.Background(), err)
	os.Exit(1)
}

func getXDGDataDir() string {
	if s := os.Getenv("XDG_DATA_HOME"); s != "" {
		return path.Join(filepath.ToSlash(s), "bitcensus")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return path.Join(filepath.ToSlash(home), ".local", "share", "bitcensus")
	}
	return ""
}
