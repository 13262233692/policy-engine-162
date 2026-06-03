package opa

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"log"
	"strings"

	"github.com/policy-engine/engine/internal/policy"
)

type Decision struct {
	Allowed     bool                   `json:"allowed"`
	Denied      bool                   `json:"denied"`
	Reason      string                 `json:"reason,omitempty"`
	Obligations map[string]interface{} `json:"obligations,omitempty"`
	QueryTime   time.Duration          `json:"query_time"`
}

type ABACInput struct {
	Subject  map[string]interface{} `json:"subject"`
	Resource map[string]interface{} `json:"resource"`
	Action   map[string]interface{} `json:"action"`
	Context  map[string]interface{} `json:"context"`
}

type Engine struct {
	mu        sync.RWMutex
	compiler  *ast.Compiler
	store     storage.Store
	policyDir string
}

func NewEngine(policyDir string) *Engine {
	return &Engine{
		policyDir: policyDir,
	}
}

func (e *Engine) InitFromLoader(loader *policy.Loader) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	policies := loader.GetAll()
	modules := make(map[string]string, len(policies))
	for id, p := range policies {
		moduleName := id
		if !strings.Contains(moduleName, "/") {
			moduleName = "abac/" + moduleName
		}
		modules[moduleName] = p.Content
	}

	compiler, err := ast.CompileModulesWithOpt(modules, ast.CompileOpts{
		ParserOptions: ast.ParserOptions{
			AllFutureKeywords: true,
			RegoVersion:       ast.RegoV0CompatV1,
		},
	})
	if err != nil {
		return fmt.Errorf("compile rego modules: %w", err)
	}

	store := inmem.New()

	ctx := context.Background()
	if err := e.loadDataIntoStore(ctx, store); err != nil {
		log.Printf("[opa-engine] warning: failed to load data: %v", err)
	}

	e.compiler = compiler
	e.store = store

	log.Printf("[opa-engine] compiled %d policy modules", len(modules))
	return nil
}

func (e *Engine) loadDataIntoStore(ctx context.Context, store storage.Store) error {
	dataDir := filepath.Join(filepath.Dir(e.policyDir), "data")
	dataFile := filepath.Join(dataDir, "data.json")

	content, err := os.ReadFile(dataFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read data file: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(content, &data); err != nil {
		return fmt.Errorf("parse data JSON: %w", err)
	}

	txn, err := store.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		return fmt.Errorf("create transaction: %w", err)
	}

	for k, v := range data {
		path, ok := storage.ParsePath("/" + k)
		if !ok {
			store.Abort(ctx, txn)
			return fmt.Errorf("parse path for key %s", k)
		}
		if err := store.Write(ctx, txn, storage.AddOp, path, v); err != nil {
			store.Abort(ctx, txn)
			return fmt.Errorf("write data key %s: %w", k, err)
		}
	}

	if err := store.Commit(ctx, txn); err != nil {
		return fmt.Errorf("commit data transaction: %w", err)
	}

	log.Printf("[opa-engine] loaded data from %s", dataFile)
	return nil
}

func (e *Engine) Evaluate(ctx context.Context, input ABACInput) (*Decision, error) {
	e.mu.RLock()
	compiler := e.compiler
	store := e.store
	e.mu.RUnlock()

	if compiler == nil {
		return nil, fmt.Errorf("engine not initialized: no compiled policies")
	}

	start := time.Now()

	regoQuery := rego.New(
		rego.Query("data.abac.allow"),
		rego.Compiler(compiler),
		rego.Store(store),
		rego.Input(input),
	)

	rs, err := regoQuery.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("rego evaluation failed: %w", err)
	}

	elapsed := time.Since(start)
	decision := &Decision{
		QueryTime: elapsed,
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		decision.Denied = true
		decision.Reason = "no policy matched; default deny"
		return decision, nil
	}

	allowed, ok := rs[0].Expressions[0].Value.(bool)
	if !ok {
		decision.Denied = true
		decision.Reason = "policy returned non-boolean result; default deny"
		return decision, nil
	}

	if allowed {
		decision.Allowed = true
		e.evaluateObligations(ctx, compiler, store, input, decision)
	} else {
		decision.Denied = true
		decision.Reason = e.evaluateDenyReason(ctx, compiler, store, input)
	}

	return decision, nil
}

func (e *Engine) evaluateObligations(ctx context.Context, compiler *ast.Compiler, store storage.Store, input ABACInput, decision *Decision) {
	obligQuery := rego.New(
		rego.Query("data.abac.obligations"),
		rego.Compiler(compiler),
		rego.Store(store),
		rego.Input(input),
	)

	obligRs, err := obligQuery.Eval(ctx)
	if err != nil || len(obligRs) == 0 || len(obligRs[0].Expressions) == 0 {
		return
	}

	if obl, ok := obligRs[0].Expressions[0].Value.(map[string]interface{}); ok {
		decision.Obligations = obl
	}
}

func (e *Engine) evaluateDenyReason(ctx context.Context, compiler *ast.Compiler, store storage.Store, input ABACInput) string {
	reasonQuery := rego.New(
		rego.Query("data.abac.deny_reason"),
		rego.Compiler(compiler),
		rego.Store(store),
		rego.Input(input),
	)

	reasonRs, err := reasonQuery.Eval(ctx)
	if err != nil || len(reasonRs) == 0 || len(reasonRs[0].Expressions) == 0 {
		return "access denied by policy"
	}

	if reason, ok := reasonRs[0].Expressions[0].Value.(string); ok {
		return reason
	}

	return "access denied by policy"
}

func (e *Engine) ReloadPolicies(loader *policy.Loader) error {
	return e.InitFromLoader(loader)
}

func (e *Engine) ReloadData() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	store := inmem.New()

	ctx := context.Background()
	if err := e.loadDataIntoStore(ctx, store); err != nil {
		return fmt.Errorf("reload data failed: %w", err)
	}

	e.store = store
	return nil
}

func (e *Engine) IsReady() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.compiler != nil
}
