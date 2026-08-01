package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/0xKirisame/shinkai-shoujo/internal/api"
	"github.com/0xKirisame/shinkai-shoujo/internal/config"
	"github.com/0xKirisame/shinkai-shoujo/internal/correlation"
	"github.com/0xKirisame/shinkai-shoujo/internal/generator"
	"github.com/0xKirisame/shinkai-shoujo/internal/metrics"
	"github.com/0xKirisame/shinkai-shoujo/internal/receiver"
	"github.com/0xKirisame/shinkai-shoujo/internal/scraper"
	"github.com/0xKirisame/shinkai-shoujo/internal/storage"
)

type contextKey int

const (
	keyConfig contextKey = iota
	keyDB
	keyMetrics
	keyLogger
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func ctxConfig(ctx context.Context) (*config.Config, bool) {
	v, ok := ctx.Value(keyConfig).(*config.Config)
	return v, ok && v != nil
}

func ctxDB(ctx context.Context) (*storage.DB, bool) {
	v, ok := ctx.Value(keyDB).(*storage.DB)
	return v, ok && v != nil
}

func ctxMetrics(ctx context.Context) (*metrics.Metrics, bool) {
	v, ok := ctx.Value(keyMetrics).(*metrics.Metrics)
	return v, ok && v != nil
}

func ctxLogger(ctx context.Context) (*slog.Logger, bool) {
	v, ok := ctx.Value(keyLogger).(*slog.Logger)
	return v, ok && v != nil
}

func mustFromCtx(cmd *cobra.Command) (*config.Config, *storage.DB, *metrics.Metrics, *slog.Logger) {
	ctx := cmd.Context()
	cfg, ok1 := ctxConfig(ctx)
	db, ok2 := ctxDB(ctx)
	m, ok3 := ctxMetrics(ctx)
	logger, ok4 := ctxLogger(ctx)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		panic("BUG: context values not set; PersistentPreRunE must have been skipped")
	}
	return cfg, db, m, logger
}

func rootCmd() *cobra.Command {
	var cfgPath string
	var verbose bool

	root := &cobra.Command{
		Use:   "shinkai-shoujo",
		Short: "Correlate AWS IAM permissions with OTel events in ClickHouse",
		Long: `shinkai-shoujo stores OpenTelemetry (OTel) AWS usage events in ClickHouse
and correlates them with complete IAM identity-policy snapshots to identify candidate unused privileges.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if skipsRootSetup(cmd) {
				return nil
			}

			logger := newLogger(verbose)
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}

			db, err := storage.Open(cmd.Context(), storage.Options{
				Addresses:     cfg.ClickHouse.Addresses,
				Database:      cfg.ClickHouse.Database,
				Username:      cfg.ClickHouse.Username,
				Password:      cfg.ClickHouse.Password,
				Secure:        cfg.ClickHouse.Secure,
				DialTimeout:   cfg.ClickHouse.DialTimeout,
				RetentionDays: cfg.ClickHouse.RetentionDays,
			})
			if err != nil {
				return fmt.Errorf("opening ClickHouse storage: %w", err)
			}

			ctx := context.WithValue(cmd.Context(), keyConfig, cfg)
			ctx = context.WithValue(ctx, keyDB, db)
			ctx = context.WithValue(ctx, keyMetrics, metrics.New())
			ctx = context.WithValue(ctx, keyLogger, logger)
			cmd.SetContext(ctx)
			return nil
		},
	}

	root.PersistentFlags().StringVarP(&cfgPath, "config", "c", config.DefaultConfigPath(), "config file path")
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose (debug) logging")
	root.AddCommand(
		initCmd(&cfgPath),
		scrapeCmd(),
		analyzeCmd(),
		reportCmd(),
		generateCmd(),
		daemonCmd(),
	)
	return root
}

func skipsRootSetup(cmd *cobra.Command) bool {
	for current := cmd; current != nil; current = current.Parent() {
		switch current.Name() {
		case "init", "help", "completion":
			return true
		}
	}
	return false
}

func initCmd(cfgPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create a default configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			path := *cfgPath
			if _, err := os.Stat(path); err == nil {
				fmt.Fprintf(os.Stderr, "Config already exists at %s\n", path)
				return nil
			} else if !os.IsNotExist(err) {
				return fmt.Errorf("checking config file: %w", err)
			}

			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				return fmt.Errorf("creating config directory: %w", err)
			}
			data, err := yaml.Marshal(config.DefaultConfig())
			if err != nil {
				return fmt.Errorf("marshaling default config: %w", err)
			}
			file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return fmt.Errorf("creating config file: %w", err)
			}
			if _, err := file.Write(data); err != nil {
				_ = file.Close()
				_ = os.Remove(path)
				return fmt.Errorf("writing config file: %w", err)
			}
			if err := file.Close(); err != nil {
				_ = os.Remove(path)
				return fmt.Errorf("closing config file: %w", err)
			}

			fmt.Printf("Created config at %s\n", path)
			fmt.Println("Edit it to configure AWS, ClickHouse, and the OTLP logs endpoint.")
			return nil
		},
	}
}

func scrapeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scrape",
		Short: "Save a complete IAM identity-policy snapshot to ClickHouse",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, db, m, logger := mustFromCtx(cmd)
			defer db.Close()
			_, err := scrapeSnapshot(cmd.Context(), cfg, db, m, logger)
			return err
		},
	}
}

func scrapeSnapshot(ctx context.Context, cfg *config.Config, db *storage.DB, m *metrics.Metrics, logger *slog.Logger) (storage.IAMSnapshot, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.AWS.Region))
	if err != nil {
		return storage.IAMSnapshot{}, fmt.Errorf("loading configured AWS credential chain: %w", err)
	}

	logger.Info("scraping complete IAM identity-policy snapshot", "account", cfg.AWS.AccountID)
	snapshot, err := scraper.New(awsCfg, logger).ScrapeSnapshot(ctx, cfg.AWS.AccountID)
	if err != nil {
		return storage.IAMSnapshot{}, fmt.Errorf("scraping IAM snapshot: %w", err)
	}
	if err := db.SaveIAMSnapshot(ctx, snapshot); err != nil {
		return storage.IAMSnapshot{}, fmt.Errorf("saving IAM snapshot to ClickHouse: %w", err)
	}

	m.IAMRolesScraped.Set(float64(len(snapshot.Roles)))
	logger.Info("IAM snapshot saved",
		"snapshot_id", snapshot.SnapshotID,
		"account_id", snapshot.AccountID,
		"roles", len(snapshot.Roles),
	)
	fmt.Printf("Saved IAM snapshot %s for account %s (%d roles)\n", snapshot.SnapshotID, snapshot.AccountID, len(snapshot.Roles))
	return snapshot, nil
}

func analyzeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "analyze",
		Short: "Scrape IAM and run a conservative correlation analysis",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, db, m, logger := mustFromCtx(cmd)
			defer db.Close()
			return runAnalyze(cmd.Context(), cfg, db, m, logger)
		},
	}
}

func runAnalyze(ctx context.Context, cfg *config.Config, db *storage.DB, m *metrics.Metrics, logger *slog.Logger) error {
	snapshot, err := scrapeSnapshot(ctx, cfg, db, m, logger)
	if err != nil {
		return err
	}

	engine := correlation.NewEngine(db, "default", snapshot.AccountID, cfg.Observation.WindowDays, cfg.Observation.MinObservationDay, logger, m)
	results, err := engine.Run(ctx, snapshot)
	if err != nil {
		return fmt.Errorf("running correlation: %w", err)
	}

	candidateUnused := 0
	unresolved := 0
	for _, result := range results {
		candidateUnused += len(result.Unused)
		unresolved += len(result.Unresolved)
	}
	fmt.Println("\n=== Conservative Analysis Summary ===")
	fmt.Printf("Snapshot: %s\n", snapshot.SnapshotID)
	fmt.Printf("Account: %s\n", snapshot.AccountID)
	fmt.Printf("IAM roles in snapshot: %d\n", len(snapshot.Roles))
	fmt.Printf("Roles with observed events: %d\n", len(results))
	fmt.Printf("Candidate unused privileges: %d\n", candidateUnused)
	fmt.Printf("Unresolved privileges: %d\n", unresolved)
	fmt.Println("Candidates require review; wildcard, conditional, and otherwise unresolved permissions are not removal recommendations.")
	return nil
}

func reportCmd() *cobra.Command {
	var accountID string
	var tenantID string

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Analyze and report from the latest IAM snapshot",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, db, m, logger := mustFromCtx(cmd)
			defer db.Close()

			account, tenant, err := analysisScope(cfg, accountID, tenantID)
			if err != nil {
				return err
			}
			snapshot, err := latestSnapshot(cmd.Context(), db, account)
			if err != nil {
				return err
			}
			results, err := correlation.NewEngine(db, tenant, account, cfg.Observation.WindowDays, cfg.Observation.MinObservationDay, logger, m).Run(cmd.Context(), snapshot)
			if err != nil {
				return fmt.Errorf("running correlation: %w", err)
			}

			fmt.Printf("Snapshot %s, account %s, tenant %s, collected %s\n\n",
				snapshot.SnapshotID, snapshot.AccountID, tenant, snapshot.CollectedAt.Format(time.RFC3339))
			fmt.Printf("%-60s  %-8s  %5s  %9s  %10s  %-20s  %10s\n",
				"Role", "Risk", "Used", "Candidate", "Unresolved", "Last use", "Frequency")
			fmt.Println(strings.Repeat("-", 139))
			for _, result := range results {
				lastUse, frequency := usageSummary(result.Usage)
				lastUseText := "-"
				if !lastUse.IsZero() {
					lastUseText = lastUse.UTC().Format(time.RFC3339)
				}
				fmt.Printf("%-60s  %-8s  %5d  %9d  %10d  %-20s  %10d\n",
					result.IAMRole, result.RiskLevel, len(result.Used), len(result.Unused), len(result.Unresolved), lastUseText, frequency)
			}
			if len(results) == 0 {
				fmt.Println("No roles had usage events in the observation window.")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&accountID, "account-id", "", "AWS account ID (default: aws.account_id from config)")
	cmd.Flags().StringVar(&tenantID, "tenant-id", "", "tenant ID (default: default)")
	return cmd
}

func usageSummary(usage []correlation.ActionUsage) (time.Time, uint64) {
	var lastUse time.Time
	var frequency uint64
	for _, item := range usage {
		frequency += item.SuccessfulEvents
		if item.LastSuccess.After(lastUse) {
			lastUse = item.LastSuccess
		}
	}
	return lastUse, frequency
}

func generateCmd() *cobra.Command {
	var outputFile string
	var accountID string
	var tenantID string

	cmd := &cobra.Command{
		Use:   "generate [terraform|json|yaml]",
		Short: "Generate output from the latest IAM snapshot",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, db, m, logger := mustFromCtx(cmd)
			defer db.Close()

			output, err := generator.New(args[0])
			if err != nil {
				return err
			}
			account, tenant, err := analysisScope(cfg, accountID, tenantID)
			if err != nil {
				return err
			}
			snapshot, err := latestSnapshot(cmd.Context(), db, account)
			if err != nil {
				return err
			}
			results, err := correlation.NewEngine(db, tenant, account, cfg.Observation.WindowDays, cfg.Observation.MinObservationDay, logger, m).Run(cmd.Context(), snapshot)
			if err != nil {
				return fmt.Errorf("running correlation: %w", err)
			}

			if outputFile == "" || outputFile == "-" {
				return output.Generate(results, os.Stdout)
			}
			if err := generateAtomic(output, results, outputFile); err != nil {
				return err
			}
			fmt.Printf("Output written to %s\n", outputFile)
			return nil
		},
	}
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file (default: stdout)")
	cmd.Flags().StringVar(&accountID, "account-id", "", "AWS account ID (default: aws.account_id from config)")
	cmd.Flags().StringVar(&tenantID, "tenant-id", "", "tenant ID (default: default)")
	return cmd
}

func analysisScope(cfg *config.Config, accountID, tenantID string) (string, string, error) {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		accountID = strings.TrimSpace(cfg.AWS.AccountID)
	}
	if accountID == "" {
		return "", "", fmt.Errorf("account ID is required; set aws.account_id or pass --account-id")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = "default"
	}
	return accountID, tenantID, nil
}

func latestSnapshot(ctx context.Context, db *storage.DB, accountID string) (storage.IAMSnapshot, error) {
	snapshot, found, err := db.LatestIAMSnapshot(ctx, accountID)
	if err != nil {
		return storage.IAMSnapshot{}, fmt.Errorf("reading latest IAM snapshot from ClickHouse: %w", err)
	}
	if !found {
		return storage.IAMSnapshot{}, fmt.Errorf("no IAM snapshot found for account %s; run 'shinkai-shoujo scrape' first", accountID)
	}
	return snapshot, nil
}

func generateAtomic(output generator.Generator, results []correlation.Result, destination string) error {
	directory := filepath.Dir(destination)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(destination)+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temporary output file: %w", err)
	}
	temporaryName := temporary.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(temporaryName)
		}
	}()

	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("securing temporary output file: %w", err)
	}
	if err := output.Generate(results, temporary); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("syncing output file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("closing output file: %w", err)
	}
	if err := os.Rename(temporaryName, destination); err != nil {
		return fmt.Errorf("replacing output file: %w", err)
	}
	keep = true
	return nil
}

func daemonCmd() *cobra.Command {
	var intervalText string

	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Receive OTLP logs, serve the query API, and snapshot IAM periodically",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, db, m, logger := mustFromCtx(cmd)
			defer db.Close()

			interval, err := parseDuration(intervalText)
			if err != nil {
				return fmt.Errorf("invalid snapshot interval %q: %w", intervalText, err)
			}
			return runDaemon(cmd.Context(), cfg, db, m, logger, interval)
		},
	}
	cmd.Flags().StringVar(&intervalText, "interval", "6h", "IAM snapshot interval (e.g. 1h, 7d, 30m)")
	return cmd
}

func runDaemon(parent context.Context, cfg *config.Config, db *storage.DB, m *metrics.Metrics, logger *slog.Logger, interval time.Duration) error {
	ctx, stopSignals := signal.NotifyContext(parent, syscall.SIGTERM, syscall.SIGINT)
	defer stopSignals()
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	recv, err := receiver.New(cfg.OTel.Endpoint, cfg.OTel.RoleAttribute, cfg.OTel.AuthToken, db, logger, m)
	if err != nil {
		return fmt.Errorf("creating OTLP logs receiver: %w", err)
	}
	apiServer := &http.Server{
		Addr: cfg.HTTP.Endpoint,
		Handler: api.NewHandler(db, m, logger, api.Config{
			DefaultTenantID:    "default",
			DefaultAccountID:   cfg.AWS.AccountID,
			DefaultWindowDays:  cfg.Observation.WindowDays,
			MinObservationDays: cfg.Observation.MinObservationDay,
			AuthToken:          cfg.HTTP.AuthToken,
		}),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	fatalErrors := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		if err := recv.Start(runCtx); err != nil && runCtx.Err() == nil {
			fatalErrors <- fmt.Errorf("OTLP logs receiver failed: %w", err)
		}
	}()
	go func() {
		defer workers.Done()
		logger.Info("query API listening", "addr", cfg.HTTP.Endpoint)
		if err := apiServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fatalErrors <- fmt.Errorf("query API failed: %w", err)
		}
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	scrapeResults := make(chan error, 1)
	scrapeRunning := false
	launchScrape := func() {
		if scrapeRunning {
			logger.Warn("IAM snapshot scrape still running; skipping interval")
			return
		}
		scrapeRunning = true
		workers.Add(1)
		go func() {
			defer workers.Done()
			_, err := scrapeSnapshot(runCtx, cfg, db, m, logger)
			scrapeResults <- err
		}()
	}

	logger.Info("daemon started", "snapshot_interval", interval)
	launchScrape()

	var runErr error
running:
	for {
		select {
		case <-ctx.Done():
			break running
		case err := <-fatalErrors:
			runErr = err
			break running
		case err := <-scrapeResults:
			scrapeRunning = false
			if err != nil {
				logger.Error("periodic IAM snapshot failed; OTLP ingestion remains active", "error", err)
			}
		case <-ticker.C:
			launchScrape()
		}
	}

	cancel()
	// The receiver has its own 10-second graceful shutdown window. Give all
	// workers a little longer, but never wait without a deadline.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	shutdownErr := apiServer.Shutdown(shutdownCtx)

	waited := make(chan struct{})
	go func() {
		workers.Wait()
		close(waited)
	}()
	select {
	case <-waited:
	case <-shutdownCtx.Done():
		_ = apiServer.Close()
		if shutdownErr == nil {
			shutdownErr = fmt.Errorf("daemon shutdown deadline exceeded: %w", shutdownCtx.Err())
		}
	}

	if shutdownErr != nil && !errors.Is(shutdownErr, http.ErrServerClosed) {
		if runErr != nil {
			return errors.Join(runErr, fmt.Errorf("shutting down query API: %w", shutdownErr))
		}
		return fmt.Errorf("shutting down query API: %w", shutdownErr)
	}
	return runErr
}

func newLogger(verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

func parseDuration(value string) (time.Duration, error) {
	if strings.HasSuffix(value, "d") {
		days, err := strconv.ParseInt(strings.TrimSuffix(value, "d"), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid day value: %w", err)
		}
		if days <= 0 {
			return 0, fmt.Errorf("day value must be positive")
		}
		const maxDurationDays = int64((1<<63 - 1) / int64(24*time.Hour))
		if days > maxDurationDays {
			return 0, fmt.Errorf("day value is too large")
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, err
	}
	if duration <= 0 {
		return 0, fmt.Errorf("duration must be positive")
	}
	return duration, nil
}
