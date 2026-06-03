package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gin-gonic/gin"
	"log"

	"github.com/policy-engine/engine/internal/api"
	"github.com/policy-engine/engine/internal/attribute"
	"github.com/policy-engine/engine/internal/cache"
	"github.com/policy-engine/engine/internal/opa"
	"github.com/policy-engine/engine/internal/policy"
	"github.com/policy-engine/engine/internal/simulation"
)

func main() {
	policyDir := flag.String("policy-dir", "./policies", "directory containing Rego policy files")
	addr := flag.String("addr", ":8080", "server listen address")
	cacheSize := flag.Int("cache-size", 1024, "decision cache size (LRU entries)")
	cacheTTL := flag.Duration("cache-ttl", 5*time.Minute, "decision cache TTL")
	cleanupInterval := flag.Duration("cache-cleanup", 1*time.Minute, "cache cleanup interval")
	flag.Parse()

	var err error

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("=== Policy Evaluation Engine (ABAC) ===")
	log.Printf("policy-dir: %s", *policyDir)

	if err := os.MkdirAll(*policyDir, 0755); err != nil {
		log.Fatalf("failed to create policy directory: %v", err)
	}

	opaEngine := opa.NewEngine(*policyDir)

	resolver := attribute.NewResolver()
	resolver.RegisterSource(&attribute.StaticSource{})
	resolver.RegisterSource(attribute.NewEnvironmentSource())

	resolver.AddStaticAttributes("subject", "admin@example.com", map[string]interface{}{
		"department": "engineering",
		"clearance":  "top-secret",
		"location":   "hq",
	})
	resolver.AddStaticAttributes("resource", "doc-001", map[string]interface{}{
		"department":    "engineering",
		"classification": "confidential",
		"type":          "document",
	})

	decisionCache, err := cache.NewDecisionCache(*cacheSize, *cacheTTL)
	if err != nil {
		log.Fatalf("failed to initialize decision cache: %v", err)
	}
	decisionCache.StartCleanup(*cleanupInterval)

	dataDir := filepath.Join(filepath.Dir(*policyDir), "data")
	if err := startDataWatcher(dataDir, opaEngine, decisionCache); err != nil {
		log.Printf("[main] warning: data watcher failed to start: %v", err)
	}

	var loader *policy.Loader
	loader, err = policy.NewLoader(*policyDir, func() {
		log.Println("[main] policy change detected, reloading engine...")
		if err := opaEngine.ReloadPolicies(loader); err != nil {
			log.Printf("[main] engine reload failed: %v", err)
		} else {
			log.Println("[main] engine reloaded successfully")
		}
		decisionCache.InvalidateAll()
		log.Println("[main] decision cache invalidated due to policy change")
	})
	if err != nil {
		log.Fatalf("failed to initialize policy loader: %v", err)
	}
	defer loader.Stop()

	if err := opaEngine.InitFromLoader(loader); err != nil {
		log.Fatalf("failed to initialize OPA engine: %w", err)
	}

	simEngine, err := simulation.NewEngine(*policyDir, dataDir)
	if err != nil {
		log.Printf("[main] warning: simulation engine failed to initialize: %v", err)
		simEngine = nil
	}

	handler := api.NewHandler(opaEngine, loader, resolver, decisionCache, simEngine)

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(requestLogger())

	handler.RegisterRoutes(router)

	srv := &http.Server{
		Addr:         *addr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("starting server on %s", *addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	printStartupBanner(*addr, *policyDir)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("server forced shutdown: %v", err)
	}

	loader.Stop()
	log.Println("server exited")
}

func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		c.Next()
		latency := time.Since(start)
		log.Printf("[%s] %s %s %d %v",
			c.Request.Method, path, c.ClientIP(), c.Writer.Status(), latency)
	}
}

func startDataWatcher(dataDir string, opaEngine *opa.Engine, decisionCache *cache.DecisionCache) error {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create file watcher: %w", err)
	}

	if err := watcher.Add(dataDir); err != nil {
		watcher.Close()
		return fmt.Errorf("add data directory to watcher: %w", err)
	}

	var debounceTimer *time.Timer

	go func() {
		defer watcher.Close()
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Create | fsnotify.Write | fsnotify.Remove | fsnotify.Rename) {
					if debounceTimer != nil {
						debounceTimer.Stop()
					}
					debounceTimer = time.AfterFunc(500*time.Millisecond, func() {
						log.Println("[main] data file change detected, reloading data...")
						if err := opaEngine.ReloadData(); err != nil {
							log.Printf("[main] data reload failed: %v", err)
							return
						}
						decisionCache.InvalidateAll()
						log.Println("[main] data reloaded and decision cache invalidated")
					})
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("[main] data watcher error: %v", err)
			}
		}
	}()

	log.Printf("[main] data watcher started for %s", dataDir)
	return nil
}

func printStartupBanner(addr string, policyDir string) {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║     Policy Evaluation Engine (ABAC) - Ready          ║")
	fmt.Println("╠══════════════════════════════════════════════════════╣")
	fmt.Printf("║  Address:    %-40s║\n", addr)
	fmt.Printf("║  Policies:   %-40s║\n", policyDir)
	fmt.Println("╠══════════════════════════════════════════════════════╣")
	fmt.Println("║  API Endpoints:                                      ║")
	fmt.Printf("║    POST %-44s║\n", "/api/v1/evaluate")
	fmt.Printf("║    GET  %-44s║\n", "/api/v1/health")
	fmt.Println("╠══════════════════════════════════════════════════════╣")
	fmt.Println("║  Policies:                                           ║")
	fmt.Printf("║    GET  %-44s║\n", "/api/v1/policies")
	fmt.Printf("║    POST %-44s║\n", "/api/v1/policies")
	fmt.Printf("║    GET  %-44s║\n", "/api/v1/policies/:id")
	fmt.Printf("║    PUT  %-44s║\n", "/api/v1/policies/:id")
	fmt.Printf("║    DEL  %-44s║\n", "/api/v1/policies/:id")
	fmt.Printf("║    POST %-44s║\n", "/api/v1/policies/reload")
	fmt.Println("╠══════════════════════════════════════════════════════╣")
	fmt.Println("║  Simulation & Impact Analysis:                       ║")
	fmt.Printf("║    POST %-44s║\n", "/api/v1/simulation/evaluate")
	fmt.Printf("║    POST %-44s║\n", "/api/v1/simulation/analyze/policy")
	fmt.Printf("║    POST %-44s║\n", "/api/v1/simulation/analyze/data")
	fmt.Printf("║    POST %-44s║\n", "/api/v1/simulation/refresh")
	fmt.Println("╠══════════════════════════════════════════════════════╣")
	fmt.Println("║  Cache:                                              ║")
	fmt.Printf("║    GET  %-44s║\n", "/api/v1/cache/stats")
	fmt.Printf("║    DEL  %-44s║\n", "/api/v1/cache/invalidate")
	fmt.Println("╠══════════════════════════════════════════════════════╣")
	fmt.Println("║  Attributes:                                         ║")
	fmt.Printf("║    POST %-44s║\n", "/api/v1/attributes/static/:type/:id")
	fmt.Printf("║    DEL  %-44s║\n", "/api/v1/attributes/static/:type/:id")
	fmt.Println("╚══════════════════════════════════════════════════════╝")
	fmt.Println()
}
