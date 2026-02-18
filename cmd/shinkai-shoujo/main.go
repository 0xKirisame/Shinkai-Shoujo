package main

import (
	"context"
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

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"

	"github.com/0xKirisame/shinkai-shoujo/internal/config"
	"github.com/0xKirisame/shinkai-shoujo/internal/correlation"
	"github.com/0xKirisame/shinkai-shoujo/internal/generator"
	"github.com/0xKirisame/shinkai-shoujo/internal/metrics"
	"github.com/0xKirisame/shinkai-shoujo/internal/receiver"
	"github.com/0xKirisame/shinkai-shoujo/internal/scraper"
	"github.com/0xKirisame/shinkai-shoujo/internal/storage"
)

// contextKey is a private type to avoid key collisions in context.
type contextKey int

const (
	keyConfig  contextKey = iota
	keyDB      contextKey = iota
	keyMetrics contextKey = iota
	keyLogger  contextKey = iota
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

// --- context helpers (safe type assertions) ---

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

// mustFromCtx is used in RunE handlers where PersistentPreRunE guarantees values are set.
// It panics only if there is a programming error (PersistentPreRunE was bypassed).
func mustFromCtx(cmd *cobra.Command) (*config.Config, *storage.DB, *metrics.Metrics, *slog.Logger) {
	ctx := cmd.Context()
	cfg, ok1 := ctxConfig(ctx)
	db, ok2 := ctxDB(ctx)
	m, ok3 := ctxMetrics(ctx)
	log, ok4 := ctxLogger(ctx)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		panic("BUG: context values not set — PersistentPreRunE must have been skipped")
	}
	return cfg, db, m, log
}

// --- Root command ---

func rootCmd() *cobra.Command {
	var cfgPath string
	var verbose bool

	root := &cobra.Command{
		Use:   "shinkai-shoujo",
		Short: "Identify unused AWS IAM privileges via OTel traces",
		Long: `shinkai-shoujo correlates OpenTelemetry traces against IAM-assigned
permissions to identify unused privileges. Requires read-only IAM access.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Skip setup for init — it needs no config or DB.
			if cmd.Name() == "init" {
				return nil
			}

			log := newLogger(verbose)

			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}

			db, err := storage.Open(cfg.Storage.Path)
			if err != nil {
				return fmt.Errorf("opening database: %w", err)
			}

			m := metrics.New()

			cmd.SetContext(context.WithValue(
				context.WithValue(
					context.WithValue(
						context.WithValue(cmd.Context(), keyConfig, cfg),
						keyDB, db,
					),
					keyMetrics, m,
				),
				keyLogger, log,
			))
			return nil
		},
	}

	defaultCfg := config.DefaultConfigPath()
	root.PersistentFlags().StringVarP(&cfgPath, "config", "c", defaultCfg, "config file path")
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose (debug) logging")

	root.AddCommand(
		initCmd(),
		analyzeCmd(),
		reportCmd(),
		generateCmd(),
		daemonCmd(),
	)

	return root
}

// --- init command ---

func initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create a default configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgPath := config.DefaultConfigPath()
			if _, err := os.Stat(cfgPath); err == nil {
				fmt.Fprintf(os.Stderr, "Config already exists at %s\n", cfgPath)
				return nil
			}

			if err := os.MkdirAll(filepath.Dir(cfgPath), 0755); err != nil {
				return fmt.Errorf("creating config directory: %w", err)
			}

			cfg := config.DefaultConfig()
			data, err := yaml.Marshal(cfg)
			if err != nil {
				return fmt.Errorf("marshaling default config: %w", err)
			}

			if err := os.WriteFile(cfgPath, data, 0600); err != nil {
				return fmt.Errorf("writing config file: %w", err)
			}

			fmt.Printf("Created config at %s\n", cfgPath)
			fmt.Printf("Edit the file to configure your AWS region, OTel endpoint, and storage path.\n")
			return nil
		},
	}
}

// --- analyze command ---

func analyzeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "analyze",
		Short: "Run a one-shot correlation analysis",
		Long:  "Scrapes IAM roles and correlates with stored OTel trace data to find unused privileges.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, db, m, log := mustFromCtx(cmd)
			defer db.Close()
			return runAnalyze(cmd.Context(), cfg, db, m, log)
		},
	}
}

// runAnalyze performs the IAM scrape + correlation pipeline and purges stale DB records.
func runAnalyze(ctx context.Context, cfg *config.Config, db *storage.DB, m *metrics.Metrics, log *slog.Logger) error {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.AWS.Region))
	if err != nil {
		return fmt.Errorf("loading AWS config: %w", err)
	}

	sc := scraper.New(awsCfg, log)
	log.Info("scraping IAM roles...")
	assignments, err := sc.ScrapeAll(ctx)
	if err != nil {
		return fmt.Errorf("scraping IAM: %w", err)
	}
	m.IAMRolesScraped.Set(float64(len(assignments)))
	log.Info("IAM scrape complete", "roles", len(assignments))

	// Warn if the observation window is shorter than the configured minimum.
	if oldest, ok, err := db.GetOldestObservation(ctx); err != nil {
		log.Warn("could not check observation age", "error", err)
	} else if ok {
		collectedDays := int(time.Since(oldest).Hours() / 24)
		if collectedDays < cfg.Observation.MinObservationDay {
			log.Warn("observation window may be too short",
				"collected_days", collectedDays,
				"min_recommended_days", cfg.Observation.MinObservationDay,
			)
		}
	}

	engine := correlation.NewEngine(db, cfg.Observation.WindowDays, log, m)
	results, err := engine.Run(ctx, assignments)
	if err != nil {
		return fmt.Errorf("running correlation: %w", err)
	}

	// Purge privilege_usage records older than the observation window + 1 week buffer.
	cutoff := time.Now().AddDate(0, 0, -(cfg.Observation.WindowDays + 7))
	purged, err := db.PurgeOldRecords(ctx, cutoff)
	if err != nil {
		log.Warn("failed to purge old records", "error", err)
	} else if purged > 0 {
		log.Info("purged old privilege records", "count", purged)
	}

	// Print summary.
	fmt.Printf("\n=== Shinkai Shoujo Analysis Results ===\n")
	fmt.Printf("Roles analyzed: %d\n", len(results))
	for _, r := range results {
		if len(r.Unused) > 0 {
			fmt.Printf("  [%s] %s — %d unused privilege(s)\n", r.RiskLevel, r.IAMRole, len(r.Unused))
		}
	}
	fmt.Printf("\nRun 'shinkai-shoujo generate terraform' to produce Terraform output.\n")
	return nil
}

// --- report command ---

func reportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "report",
		Short: "Show the latest analysis results from the database",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, db, _, _ := mustFromCtx(cmd)
			defer db.Close()

			results, err := db.GetLatestAnalysisResults(cmd.Context())
			if err != nil {
				return fmt.Errorf("getting analysis results: %w", err)
			}
			if len(results) == 0 {
				fmt.Println("No analysis results found. Run 'shinkai-shoujo analyze' first.")
				return nil
			}

			fmt.Printf("%-60s  %-8s  %-8s  %-8s  %-8s\n",
				"Role", "Risk", "Assigned", "Used", "Unused")
			fmt.Println(strings.Repeat("-", 100))
			for _, r := range results {
				fmt.Printf("%-60s  %-8s  %-8d  %-8d  %-8d\n",
					r.IAMRole, r.RiskLevel,
					len(r.AssignedPrivs), len(r.UsedPrivs), len(r.UnusedPrivs))
			}
			return nil
		},
	}
}

// --- generate command ---

func generateCmd() *cobra.Command {
	var outputFile string

	gen := &cobra.Command{
		Use:   "generate [terraform|json|yaml]",
		Short: "Generate output from the latest analysis results",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, db, _, _ := mustFromCtx(cmd)
			defer db.Close()

			format := args[0]
			g, err := generator.New(format)
			if err != nil {
				return err
			}

			dbResults, err := db.GetLatestAnalysisResults(cmd.Context())
			if err != nil {
				return fmt.Errorf("getting analysis results: %w", err)
			}
			if len(dbResults) == 0 {
				fmt.Println("No analysis results found. Run 'shinkai-shoujo analyze' first.")
				return nil
			}

			corrResults := make([]correlation.Result, 0, len(dbResults))
			for _, r := range dbResults {
				corrResults = append(corrResults, correlation.Result{
					IAMRole:    r.IAMRole,
					Assigned:   r.AssignedPrivs,
					Used:       r.UsedPrivs,
					Unused:     r.UnusedPrivs,
					RiskLevel:  r.RiskLevel,
					AnalyzedAt: r.AnalysisDate,
				})
			}

			if outputFile == "" || outputFile == "-" {
				return g.Generate(corrResults, os.Stdout)
			}

			f, err := os.Create(outputFile)
			if err != nil {
				return fmt.Errorf("creating output file: %w", err)
			}
			defer f.Close()

			if err := g.Generate(corrResults, f); err != nil {
				return err
			}
			fmt.Printf("Output written to %s\n", outputFile)
			return nil
		},
	}

	gen.Flags().StringVarP(&outputFile, "output", "o", "", "output file (default: stdout)")
	return gen
}

// --- daemon command ---

func daemonCmd() *cobra.Command {
	var intervalStr string
	var skipIfRunning bool

	var analyzeMu  sync.Mutex
	var analyzeRunning bool

	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run continuously, re-analyzing on an interval",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, db, m, log := mustFromCtx(cmd)
			defer db.Close()

			interval, err := parseDuration(intervalStr)
			if err != nil {
				return fmt.Errorf("invalid interval %q: %w", intervalStr, err)
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, syscall.SIGINT)
			defer stop()

			// Start metrics HTTP server with graceful shutdown.
			metricsSrv := &http.Server{
				Addr:    cfg.Metrics.Endpoint,
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/metrics" {
						m.Handler().ServeHTTP(w, r)
						return
					}
					http.NotFound(w, r)
				}),
			}
			go func() {
				log.Info("metrics server listening", "addr", cfg.Metrics.Endpoint)
				if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					log.Error("metrics server error", "error", err)
				}
			}()

			// Start OTel receiver.
			recv, err := receiver.New(cfg.OTel.Endpoint, db, log, m)
			if err != nil {
				return fmt.Errorf("creating receiver: %w", err)
			}

			// Track both the receiver and all analysis goroutines.
			var wg sync.WaitGroup

			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := recv.Start(ctx); err != nil {
					log.Error("receiver stopped", "error", err)
				}
			}()

			log.Info("daemon started", "interval", interval)
			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			launchAnalysis := func() {
				if skipIfRunning {
					analyzeMu.Lock()
					if analyzeRunning {
						log.Info("analysis already running, skipping")
						analyzeMu.Unlock()
						return
					}
					analyzeRunning = true
					analyzeMu.Unlock()
				}

				wg.Add(1)
				go func() {
					defer wg.Done()
					if skipIfRunning {
						defer func() {
							analyzeMu.Lock()
							analyzeRunning = false
							analyzeMu.Unlock()
						}()
					}
					if err := runAnalyze(ctx, cfg, db, m, log); err != nil {
						log.Error("analysis failed", "error", err)
					}
				}()
			}

			// Run immediately on start.
			launchAnalysis()

			for {
				select {
				case <-ticker.C:
					launchAnalysis()
				case <-ctx.Done():
					log.Info("daemon shutting down, waiting for in-flight work...")
					wg.Wait()
					// Shut down metrics server after all goroutines are done.
					_ = metricsSrv.Shutdown(context.Background())
					return nil
				}
			}
		},
	}

	cmd.Flags().StringVar(&intervalStr, "interval", "24h", "analysis interval (e.g. 1h, 7d, 30m)")
	cmd.Flags().BoolVar(&skipIfRunning, "skip-if-running", true, "skip analysis if previous run is still active")
	return cmd
}

// --- helpers ---

func newLogger(verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))
}

// parseDuration parses a duration string, extending time.ParseDuration to support
// day suffixes ("d"). Examples: "7d", "24h", "30m".
func parseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, fmt.Errorf("invalid day value: %w", err)
		}
		if days <= 0 {
			return 0, fmt.Errorf("day value must be positive")
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
