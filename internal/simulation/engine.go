package simulation

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"

	"github.com/policy-engine/engine/internal/opa"
)

type Result struct {
	Allowed        bool                   `json:"allowed"`
	Denied         bool                   `json:"denied"`
	Reason         string                 `json:"reason,omitempty"`
	Obligations    map[string]interface{} `json:"obligations,omitempty"`
}

type Engine struct {
	mu            sync.RWMutex
	compiler      *ast.Compiler
	store         storage.Store
	basePolicies  map[string]string
	baseData      map[string]interface{}
}

func NewEngine(policyDir string, dataDir string) (*Engine, error) {
	e := &Engine{}

	basePolicies, err := loadPolicies(policyDir)
	if err != nil {
		return nil, fmt.Errorf("load base policies: %w", err)
	}
	e.basePolicies = basePolicies

	baseData, err := loadData(dataDir)
	if err != nil {
		return nil, fmt.Errorf("load base data: %w", err)
	}
	e.baseData = baseData

	if err := e.compile(basePolicies, baseData); err != nil {
		return nil, err
	}

	return e, nil
}

func loadPolicies(policyDir string) (map[string]string, error) {
	policies := make(map[string]string)

	err := filepath.Walk(policyDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".rego" {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		relPath, _ := filepath.Rel(policyDir, path)
		id := relPath
		id = filepath.ToSlash(id)
		id = id[:len(id)-5]

		policies[id] = string(content)
		return nil
	})

	return policies, err
}

func loadData(dataDir string) (map[string]interface{}, error) {
	dataFile := filepath.Join(dataDir, "data.json")
	content, err := os.ReadFile(dataFile)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]interface{}), nil
		}
		return nil, err
	}

	var data map[string]interface{}
	if err := json.Unmarshal(content, &data); err != nil {
		return nil, err
	}

	return data, nil
}

func (e *Engine) compile(policies map[string]string, data map[string]interface{}) error {
	modules := make(map[string]string)
	for id, content := range policies {
		moduleName := id
		if !filepath.IsAbs(id) && !filepath.HasPrefix(id, "abac/") {
			moduleName = "abac/" + id
		}
		modules[moduleName] = content
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

	if len(data) > 0 {
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
	}

	e.mu.Lock()
	e.compiler = compiler
	e.store = store
	e.mu.Unlock()

	return nil
}

func (e *Engine) Evaluate(ctx context.Context, input opa.ABACInput) (*Result, error) {
	e.mu.RLock()
	compiler := e.compiler
	store := e.store
	e.mu.RUnlock()

	if compiler == nil {
		return nil, fmt.Errorf("simulation engine not initialized")
	}

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

	result := &Result{}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		result.Denied = true
		result.Reason = "no policy matched; default deny"
		return result, nil
	}

	allowed, ok := rs[0].Expressions[0].Value.(bool)
	if !ok {
		result.Denied = true
		result.Reason = "policy returned non-boolean result; default deny"
		return result, nil
	}

	if allowed {
		result.Allowed = true
		e.evaluateObligations(ctx, compiler, store, input, result)
	} else {
		result.Denied = true
		result.Reason = e.evaluateDenyReason(ctx, compiler, store, input)
	}

	return result, nil
}

func (e *Engine) evaluateObligations(ctx context.Context, compiler *ast.Compiler, store storage.Store, input opa.ABACInput, result *Result) {
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
		result.Obligations = obl
	}
}

func (e *Engine) evaluateDenyReason(ctx context.Context, compiler *ast.Compiler, store storage.Store, input opa.ABACInput) string {
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

func (e *Engine) SimulateWithPolicy(ctx context.Context, policyID string, policyContent string, input opa.ABACInput) (*Result, error) {
	simPolicies := make(map[string]string)
	for k, v := range e.basePolicies {
		simPolicies[k] = v
	}
	simPolicies[policyID] = policyContent

	simEngine := &Engine{}
	if err := simEngine.compile(simPolicies, e.baseData); err != nil {
		return nil, err
	}

	return simEngine.Evaluate(ctx, input)
}

func (e *Engine) SimulateWithData(ctx context.Context, data map[string]interface{}, input opa.ABACInput) (*Result, error) {
	simData := make(map[string]interface{})
	for k, v := range e.baseData {
		simData[k] = v
	}
	for k, v := range data {
		simData[k] = v
	}

	simEngine := &Engine{}
	if err := simEngine.compile(e.basePolicies, simData); err != nil {
		return nil, err
	}

	return simEngine.Evaluate(ctx, input)
}

type ChangeType string

const (
	ChangeGranted   ChangeType = "granted"
	ChangeRevoked   ChangeType = "revoked"
	ChangeNoChange  ChangeType = "no_change"
)

type ScenarioInput struct {
	Subject  map[string]interface{} `json:"subject"`
	Resource map[string]interface{} `json:"resource"`
	Action   map[string]interface{} `json:"action"`
	Context  map[string]interface{} `json:"context"`
	Name     string                 `json:"name"`
}

type ScenarioResult struct {
	Name        string      `json:"name"`
	Input       opa.ABACInput `json:"input"`
	Before      Result      `json:"before"`
	After       Result      `json:"after"`
	Change      ChangeType  `json:"change"`
	Description string      `json:"description"`
}

type ImpactAnalysis struct {
	TotalScenarios  int            `json:"total_scenarios"`
	GrantedCount    int            `json:"granted_count"`
	RevokedCount    int            `json:"revoked_count"`
	NoChangeCount   int            `json:"no_change_count"`
	Results         []ScenarioResult `json:"results"`
	ChangeMatrix    map[string]int  `json:"change_matrix"`
}

func (e *Engine) AnalyzePolicyImpact(ctx context.Context, policyID string, policyContent string, scenarios []ScenarioInput) (*ImpactAnalysis, error) {
	simPolicies := make(map[string]string)
	for k, v := range e.basePolicies {
		simPolicies[k] = v
	}
	simPolicies[policyID] = policyContent

	simEngine := &Engine{}
	if err := simEngine.compile(simPolicies, e.baseData); err != nil {
		return nil, fmt.Errorf("compile simulated policies: %w", err)
	}

	analysis := &ImpactAnalysis{
		Results:      make([]ScenarioResult, 0, len(scenarios)),
		ChangeMatrix: make(map[string]int),
	}

	for _, s := range scenarios {
		input := opa.ABACInput{
			Subject:  s.Subject,
			Resource: s.Resource,
			Action:   s.Action,
			Context:  s.Context,
		}

		before, err := e.Evaluate(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("evaluate before for %s: %w", s.Name, err)
		}

		after, err := simEngine.Evaluate(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("evaluate after for %s: %w", s.Name, err)
		}

		change := computeChange(before, after)

		analysis.Results = append(analysis.Results, ScenarioResult{
			Name:        s.Name,
			Input:       input,
			Before:      *before,
			After:       *after,
			Change:      change,
			Description: describeChange(change, before, after),
		})

		analysis.ChangeMatrix[string(change)]++
	}

	analysis.TotalScenarios = len(analysis.Results)
	analysis.GrantedCount = analysis.ChangeMatrix[string(ChangeGranted)]
	analysis.RevokedCount = analysis.ChangeMatrix[string(ChangeRevoked)]
	analysis.NoChangeCount = analysis.ChangeMatrix[string(ChangeNoChange)]

	return analysis, nil
}

func (e *Engine) AnalyzeDataImpact(ctx context.Context, dataChanges map[string]interface{}, scenarios []ScenarioInput) (*ImpactAnalysis, error) {
	simData := make(map[string]interface{})
	for k, v := range e.baseData {
		simData[k] = v
	}
	for k, v := range dataChanges {
		simData[k] = v
	}

	simEngine := &Engine{}
	if err := simEngine.compile(e.basePolicies, simData); err != nil {
		return nil, fmt.Errorf("compile with simulated data: %w", err)
	}

	analysis := &ImpactAnalysis{
		Results:      make([]ScenarioResult, 0, len(scenarios)),
		ChangeMatrix: make(map[string]int),
	}

	for _, s := range scenarios {
		input := opa.ABACInput{
			Subject:  s.Subject,
			Resource: s.Resource,
			Action:   s.Action,
			Context:  s.Context,
		}

		before, err := e.Evaluate(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("evaluate before for %s: %w", s.Name, err)
		}

		after, err := simEngine.Evaluate(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("evaluate after for %s: %w", s.Name, err)
		}

		change := computeChange(before, after)

		analysis.Results = append(analysis.Results, ScenarioResult{
			Name:        s.Name,
			Input:       input,
			Before:      *before,
			After:       *after,
			Change:      change,
			Description: describeChange(change, before, after),
		})

		analysis.ChangeMatrix[string(change)]++
	}

	analysis.TotalScenarios = len(analysis.Results)
	analysis.GrantedCount = analysis.ChangeMatrix[string(ChangeGranted)]
	analysis.RevokedCount = analysis.ChangeMatrix[string(ChangeRevoked)]
	analysis.NoChangeCount = analysis.ChangeMatrix[string(ChangeNoChange)]

	return analysis, nil
}

func computeChange(before, after *Result) ChangeType {
	if before.Allowed && !after.Allowed {
		return ChangeRevoked
	}
	if !before.Allowed && after.Allowed {
		return ChangeGranted
	}
	return ChangeNoChange
}

func describeChange(change ChangeType, before, after *Result) string {
	switch change {
	case ChangeGranted:
		return fmt.Sprintf("权限已授予: 之前被拒绝(%s)，现在允许", before.Reason)
	case ChangeRevoked:
		return fmt.Sprintf("权限已撤销: 之前允许，现在被拒绝(%s)", after.Reason)
	default:
		return "无变化"
	}
}

func (e *Engine) Refresh() error {
	return e.compile(e.basePolicies, e.baseData)
}
