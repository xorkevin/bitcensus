package cmd

import (
	"context"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"xorkevin.dev/bitcensus/census"
	"xorkevin.dev/kerrors"
	"xorkevin.dev/klog"
)

func (c *Cmd) addCensusCmds(cmd *cobra.Command) {
	syncCmd := &cobra.Command{
		Use:               "sync",
		Short:             "Syncs repo dbs",
		Long:              `Syncs repo dbs`,
		Run:               c.execSync,
		DisableAutoGenTag: true,
	}
	syncCmd.PersistentFlags().StringVar(&c.censusFlags.stateDBDir, "state-db-dir", "", "state db directory (default is $XDG_DATA_HOME/bitcensus)")
	syncCmd.PersistentFlags().BoolVar(&c.censusFlags.prune, "prune", false, "removes deleted files from the db")
	syncCmd.PersistentFlags().BoolVarP(&c.censusFlags.update, "update", "u", false, "updates files in db even if checksum differs")
	syncCmd.PersistentFlags().BoolVarP(&c.censusFlags.checksum, "checksum", "c", false, "hashes files regardless of file size and modtime heuristic")
	syncCmd.PersistentFlags().BoolVarP(&c.censusFlags.dryRun, "dry-run", "n", false, "do not modify the db and dry run the operation")
	syncCmd.PersistentFlags().StringVarP(&c.censusFlags.repo, "repo", "r", "", "repo name (empty means all)")
	cmd.AddCommand(syncCmd)

	verifyCmd := &cobra.Command{
		Use:               "verify",
		Short:             "Verifies files",
		Long:              `Verifies files`,
		Run:               c.execVerify,
		DisableAutoGenTag: true,
	}
	verifyCmd.PersistentFlags().StringVar(&c.censusFlags.stateDBDir, "state-db-dir", "", "state db directory (default is $XDG_DATA_HOME/bitcensus)")
	verifyCmd.PersistentFlags().StringVarP(&c.censusFlags.before, "before", "b", "168h", "age of files to verify (\"now\" will verify all)")
	verifyCmd.PersistentFlags().BoolVar(&c.censusFlags.repair, "repair", false, "attempt to repair corrupted files")
	verifyCmd.PersistentFlags().StringVarP(&c.censusFlags.repo, "repo", "r", "", "repo name (empty means all)")
	cmd.AddCommand(verifyCmd)

	exportCmd := &cobra.Command{
		Use:               "export",
		Short:             "Exports repo dbs",
		Long:              `Exports repo dbs`,
		Run:               c.execExport,
		DisableAutoGenTag: true,
	}
	exportCmd.PersistentFlags().StringVar(&c.censusFlags.stateDBDir, "state-db-dir", "", "state db directory (default is $XDG_DATA_HOME/bitcensus)")
	exportCmd.PersistentFlags().StringVarP(&c.censusFlags.repo, "repo", "r", "", "repo name")
	exportCmd.MarkPersistentFlagRequired("repo")
	cmd.AddCommand(exportCmd)

	importCmd := &cobra.Command{
		Use:               "import",
		Short:             "Imports repo dbs",
		Long:              `Imports repo dbs`,
		Run:               c.execImport,
		DisableAutoGenTag: true,
	}
	importCmd.PersistentFlags().StringVar(&c.censusFlags.stateDBDir, "state-db-dir", "", "state db directory (default is $XDG_DATA_HOME/bitcensus)")
	importCmd.PersistentFlags().BoolVarP(&c.censusFlags.force, "force", "f", false, "overwrite existing files in the db")
	importCmd.PersistentFlags().StringVarP(&c.censusFlags.repo, "repo", "r", "", "repo name")
	importCmd.MarkPersistentFlagRequired("repo")
	cmd.AddCommand(importCmd)
}

func (c *Cmd) getCensus() *census.Census {
	var cfg census.SyncConfig
	if err := viper.UnmarshalKey("repos", &cfg); err != nil {
		c.logFatal(kerrors.WithMsg(err, "Failed to read repos config"))
		return nil
	}
	dbdir := c.getStateDBDir()
	return census.New(c.log.Logger, dbdir, cfg)
}

func (c *Cmd) execSync(cmd *cobra.Command, args []string) {
	cen := c.getCensus()
	flags := census.SyncFlags{
		Prune:    c.censusFlags.prune,
		Update:   c.censusFlags.update,
		Checksum: c.censusFlags.checksum,
		DryRun:   c.censusFlags.dryRun,
	}
	if c.censusFlags.repo != "" {
		if err := cen.SyncRepo(context.Background(), c.censusFlags.repo, flags); err != nil {
			c.logFatal(err)
			return
		}
	} else {
		if err := cen.SyncRepos(context.Background(), flags); err != nil {
			c.logFatal(err)
			return
		}
	}
}

func (c *Cmd) execVerify(cmd *cobra.Command, args []string) {
	cen := c.getCensus()
	var before time.Time
	timeStr := "now"
	if c.censusFlags.before != "" && c.censusFlags.before != "now" {
		dur, err := time.ParseDuration(c.censusFlags.before)
		if err != nil {
			c.logFatal(kerrors.WithMsg(err, "Invalid duration"))
			return
		}
		before = time.Now().Round(0).Add(-dur)
		timeStr = before.Format(time.RFC3339)
	}
	c.log.Info(context.Background(), "Verifying files",
		klog.AString("before", timeStr),
	)
	flags := census.VerifyFlags{
		Before: before,
		Repair: c.censusFlags.repair,
	}
	if c.censusFlags.repo != "" {
		if err := cen.VerifyRepo(context.Background(), c.censusFlags.repo, flags); err != nil {
			c.logFatal(err)
			return
		}
	} else {
		if err := cen.VerifyRepos(context.Background(), flags); err != nil {
			c.logFatal(err)
			return
		}
	}
}

func (c *Cmd) execExport(cmd *cobra.Command, args []string) {
	cen := c.getCensus()
	if c.censusFlags.repo == "" {
		c.logFatal(kerrors.WithMsg(nil, "Repo must be provided"))
		return
	}
	if err := cen.ExportRepo(context.Background(), os.Stdout, c.censusFlags.repo); err != nil {
		c.logFatal(err)
		return
	}
}

func (c *Cmd) execImport(cmd *cobra.Command, args []string) {
	cen := c.getCensus()
	if c.censusFlags.repo == "" {
		c.logFatal(kerrors.WithMsg(nil, "Repo must be provided"))
		return
	}
	if err := cen.ImportRepo(context.Background(), os.Stdin, c.censusFlags.repo, c.censusFlags.force); err != nil {
		c.logFatal(err)
		return
	}
}
