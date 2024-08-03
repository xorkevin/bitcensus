package cmd

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"xorkevin.dev/bitcensus/census"
	"xorkevin.dev/kerrors"
	"xorkevin.dev/klog"
)

type (
	Cmd struct {
		rootCmd     *cobra.Command
		log         *klog.LevelLogger
		version     string
		rootFlags   rootFlags
		censusFlags censusFlags
		docFlags    docFlags
	}

	rootFlags struct {
		cfgFile  string
		logLevel string
		logJSON  bool
	}

	censusFlags struct {
		stateDBDir string
		prune      bool
		update     bool
		checksum   bool
		force      bool
		dryRun     bool
		before     string
		repair     bool
		repo       string
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
	rootCmd.PersistentFlags().StringVar(&c.rootFlags.logLevel, "log-level", "info", "log level")
	rootCmd.PersistentFlags().BoolVar(&c.rootFlags.logJSON, "log-json", false, "output json logs")

	viper.SetDefault("statedbdir", getXDGDataDir())
	viper.SetDefault("repos", census.SyncConfig{})

	c.rootCmd = rootCmd

	c.addCensusCmds(rootCmd)
	rootCmd.AddCommand(c.getDocCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
		return
	}
}

func (c *Cmd) getStateDBDir() string {
	dbdir := c.censusFlags.stateDBDir
	if dbdir == "" {
		dbdir = viper.GetString("statedbdir")
		if dbdir == "" {
			dbdir = "."
		}
	}
	return dbdir
}

// initConfig reads in config file and ENV variables if set.
func (c *Cmd) initConfig(cmd *cobra.Command, args []string) {
	logWriter := klog.NewSyncWriter(os.Stderr)
	var handler *klog.SlogHandler
	if c.rootFlags.logJSON {
		handler = klog.NewJSONSlogHandler(logWriter)
	} else {
		handler = klog.NewTextSlogHandler(logWriter)
		handler.FieldTime = ""
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
