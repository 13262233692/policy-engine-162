package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/policy-engine/engine/internal/attribute"
	"github.com/policy-engine/engine/internal/cache"
	"github.com/policy-engine/engine/internal/opa"
	"github.com/policy-engine/engine/internal/policy"
	"github.com/policy-engine/engine/internal/simulation"
)

type Handler struct {
	engine         *opa.Engine
	loader         *policy.Loader
	resolver       *attribute.Resolver
	cache          *cache.DecisionCache
	simEngine      *simulation.Engine
}

func NewHandler(engine *opa.Engine, loader *policy.Loader, resolver *attribute.Resolver, cache *cache.DecisionCache, simEngine *simulation.Engine) *Handler {
	return &Handler{
		engine:    engine,
		loader:    loader,
		resolver:  resolver,
		cache:     cache,
		simEngine: simEngine,
	}
}

func (h *Handler) RegisterRoutes(r *gin.Engine) {
	v1 := r.Group("/api/v1")
	{
		v1.POST("/evaluate", h.Evaluate)
		v1.GET("/health", h.Health)

		policies := v1.Group("/policies")
		{
			policies.GET("", h.ListPolicies)
			policies.GET("/*id", h.GetPolicy)
			policies.POST("", h.CreatePolicy)
			policies.PUT("/*id", h.UpdatePolicy)
			policies.DELETE("/*id", h.DeletePolicy)
			policies.POST("/reload", h.ReloadPolicies)
		}

		cacheGroup := v1.Group("/cache")
		{
			cacheGroup.GET("/stats", h.CacheStats)
			cacheGroup.DELETE("/invalidate", h.CacheInvalidate)
		}

		attributes := v1.Group("/attributes")
		{
			attributes.GET("/sources", h.ListSources)
			attributes.POST("/static/:entityType/:entityID", h.SetStaticAttributes)
			attributes.DELETE("/static/:entityType/:entityID", h.RemoveStaticAttributes)
		}

		simulation := v1.Group("/simulation")
		{
			simulation.POST("/evaluate", h.SimulateEvaluate)
			simulation.POST("/analyze/policy", h.AnalyzePolicyImpact)
			simulation.POST("/analyze/data", h.AnalyzeDataImpact)
			simulation.POST("/refresh", h.SimulationRefresh)
		}
	}
}

type EvaluateRequest struct {
	Subject  map[string]interface{} `json:"subject" binding:"required"`
	Resource map[string]interface{} `json:"resource" binding:"required"`
	Action   map[string]interface{} `json:"action" binding:"required"`
	Context  map[string]interface{} `json:"context"`
}

type EvaluateResponse struct {
	Allowed     bool                   `json:"allowed"`
	Denied      bool                   `json:"denied"`
	Reason      string                 `json:"reason,omitempty"`
	Obligations map[string]interface{} `json:"obligations,omitempty"`
	QueryTime   time.Duration          `json:"query_time"`
	Cached      bool                   `json:"cached"`
	Resolved    map[string]interface{} `json:"resolved_input,omitempty"`
}

func (h *Handler) Evaluate(c *gin.Context) {
	var req EvaluateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	abacInput := opa.ABACInput{
		Subject:  req.Subject,
		Resource: req.Resource,
		Action:   req.Action,
		Context:  req.Context,
	}

	if h.cache != nil {
		if decision, ok := h.cache.Get(abacInput); ok {
			c.JSON(http.StatusOK, EvaluateResponse{
				Allowed:     decision.Allowed,
				Denied:      decision.Denied,
				Reason:      decision.Reason,
				Obligations: decision.Obligations,
				QueryTime:   decision.QueryTime,
				Cached:      true,
			})
			return
		}
	}

	if h.resolver != nil {
		rawInput := map[string]interface{}{
			"subject":  req.Subject,
			"resource": req.Resource,
			"action":   req.Action,
			"context":  req.Context,
		}

		resolved, err := h.resolver.ResolveABACInput(c.Request.Context(), rawInput)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "attribute resolution failed: " + err.Error()})
			return
		}

		abacInput.Subject, _ = resolved["subject"].(map[string]interface{})
		abacInput.Resource, _ = resolved["resource"].(map[string]interface{})
		abacInput.Action, _ = resolved["action"].(map[string]interface{})
		abacInput.Context, _ = resolved["context"].(map[string]interface{})
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	decision, err := h.engine.Evaluate(ctx, abacInput)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "evaluation failed: " + err.Error()})
		return
	}

	if h.cache != nil {
		h.cache.Set(abacInput, decision)
	}

	c.JSON(http.StatusOK, EvaluateResponse{
		Allowed:     decision.Allowed,
		Denied:      decision.Denied,
		Reason:      decision.Reason,
		Obligations: decision.Obligations,
		QueryTime:   decision.QueryTime,
		Cached:      false,
	})
}

func (h *Handler) Health(c *gin.Context) {
	ready := h.engine.IsReady()
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	c.JSON(status, gin.H{
		"status":  statusStr(ready),
		"engine":  ready,
		"policies": len(h.loader.GetAll()),
	})
}

func statusStr(ready bool) string {
	if ready {
		return "ready"
	}
	return "not_ready"
}

func (h *Handler) ListPolicies(c *gin.Context) {
	policies := h.loader.GetAll()
	list := make([]gin.H, 0, len(policies))
	for _, p := range policies {
		list = append(list, gin.H{
			"id":         p.ID,
			"name":       p.Name,
			"path":       p.Path,
			"updated_at": p.UpdatedAt,
		})
	}
	c.JSON(http.StatusOK, gin.H{"policies": list, "total": len(list)})
}

func (h *Handler) GetPolicy(c *gin.Context) {
	id := strings.TrimPrefix(c.Param("id"), "/")
	p, ok := h.loader.Get(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id":         p.ID,
		"name":       p.Name,
		"content":    p.Content,
		"path":       p.Path,
		"updated_at": p.UpdatedAt,
	})
}

type CreatePolicyRequest struct {
	ID      string `json:"id" binding:"required"`
	Content string `json:"content" binding:"required"`
}

func (h *Handler) CreatePolicy(c *gin.Context) {
	var req CreatePolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.loader.Create(req.ID, req.Content); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := h.engine.ReloadPolicies(h.loader); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "policy created but engine reload failed: " + err.Error()})
		return
	}

	if h.cache != nil {
		h.cache.InvalidateAll()
	}

	c.JSON(http.StatusCreated, gin.H{"id": req.ID, "status": "created"})
}

func (h *Handler) UpdatePolicy(c *gin.Context) {
	id := strings.TrimPrefix(c.Param("id"), "/")
	var req struct {
		Content string `json:"content" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.loader.Update(id, req.Content); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	if err := h.engine.ReloadPolicies(h.loader); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "policy updated but engine reload failed: " + err.Error()})
		return
	}

	if h.cache != nil {
		h.cache.InvalidateAll()
	}

	c.JSON(http.StatusOK, gin.H{"id": id, "status": "updated"})
}

func (h *Handler) DeletePolicy(c *gin.Context) {
	id := strings.TrimPrefix(c.Param("id"), "/")
	if err := h.loader.Delete(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	if err := h.engine.ReloadPolicies(h.loader); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "policy deleted but engine reload failed: " + err.Error()})
		return
	}

	if h.cache != nil {
		h.cache.InvalidateAll()
	}

	c.JSON(http.StatusOK, gin.H{"id": id, "status": "deleted"})
}

func (h *Handler) ReloadPolicies(c *gin.Context) {
	if err := h.engine.ReloadPolicies(h.loader); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if h.cache != nil {
		h.cache.InvalidateAll()
	}

	c.JSON(http.StatusOK, gin.H{"status": "reloaded"})
}

func (h *Handler) CacheStats(c *gin.Context) {
	if h.cache == nil {
		c.JSON(http.StatusOK, gin.H{"enabled": false})
		return
	}
	c.JSON(http.StatusOK, gin.H{"enabled": true, "stats": h.cache.Stats()})
}

func (h *Handler) CacheInvalidate(c *gin.Context) {
	if h.cache == nil {
		c.JSON(http.StatusOK, gin.H{"enabled": false})
		return
	}
	h.cache.InvalidateAll()
	c.JSON(http.StatusOK, gin.H{"status": "invalidated"})
}

func (h *Handler) ListSources(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "attribute sources are managed programmatically",
	})
}

type SetStaticAttributesRequest struct {
	Attributes map[string]interface{} `json:"attributes" binding:"required"`
}

func (h *Handler) SetStaticAttributes(c *gin.Context) {
	entityType := c.Param("entityType")
	entityID := c.Param("entityID")

	var req SetStaticAttributesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.resolver.AddStaticAttributes(entityType, entityID, req.Attributes)
	c.JSON(http.StatusOK, gin.H{
		"entity_type": entityType,
		"entity_id":   entityID,
		"status":      "set",
	})
}

func (h *Handler) RemoveStaticAttributes(c *gin.Context) {
	entityType := c.Param("entityType")
	entityID := c.Param("entityID")

	h.resolver.RemoveStaticAttributes(entityType, entityID)
	c.JSON(http.StatusOK, gin.H{
		"entity_type": entityType,
		"entity_id":   entityID,
		"status":      "removed",
	})
}

type SimulateEvaluateRequest struct {
	PolicyID      string                 `json:"policy_id"`
	PolicyContent string                 `json:"policy_content"`
	Subject       map[string]interface{} `json:"subject" binding:"required"`
	Resource      map[string]interface{} `json:"resource" binding:"required"`
	Action        map[string]interface{} `json:"action" binding:"required"`
	Context       map[string]interface{} `json:"context"`
	DataChanges   map[string]interface{} `json:"data_changes"`
}

type SimulateEvaluateResponse struct {
	Current  simulation.Result `json:"current"`
	Proposed simulation.Result `json:"proposed"`
	Change   simulation.ChangeType `json:"change"`
	Diff     string             `json:"diff"`
}

func (h *Handler) SimulateEvaluate(c *gin.Context) {
	if h.simEngine == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "simulation engine not available"})
		return
	}

	var req SimulateEvaluateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	input := opa.ABACInput{
		Subject:  req.Subject,
		Resource: req.Resource,
		Action:   req.Action,
		Context:  req.Context,
	}

	ctx := c.Request.Context()

	current, err := h.simEngine.Evaluate(ctx, input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "current evaluation failed: " + err.Error()})
		return
	}

	var proposed *simulation.Result
	if req.PolicyContent != "" {
		proposed, err = h.simEngine.SimulateWithPolicy(ctx, req.PolicyID, req.PolicyContent, input)
	} else if len(req.DataChanges) > 0 {
		proposed, err = h.simEngine.SimulateWithData(ctx, req.DataChanges, input)
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "either policy_content or data_changes must be provided"})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "proposed evaluation failed: " + err.Error()})
		return
	}

	change := computeChangeType(current, proposed)

	c.JSON(http.StatusOK, SimulateEvaluateResponse{
		Current:  *current,
		Proposed: *proposed,
		Change:   change,
		Diff:     describeDiff(change, current, proposed),
	})
}

type AnalyzePolicyRequest struct {
	PolicyID      string                   `json:"policy_id" binding:"required"`
	PolicyContent string                   `json:"policy_content" binding:"required"`
	Scenarios     []simulation.ScenarioInput `json:"scenarios" binding:"required"`
}

type AnalyzeDataRequest struct {
	DataChanges map[string]interface{}     `json:"data_changes" binding:"required"`
	Scenarios   []simulation.ScenarioInput `json:"scenarios" binding:"required"`
}

func (h *Handler) AnalyzePolicyImpact(c *gin.Context) {
	if h.simEngine == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "simulation engine not available"})
		return
	}

	var req AnalyzePolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	analysis, err := h.simEngine.AnalyzePolicyImpact(c.Request.Context(), req.PolicyID, req.PolicyContent, req.Scenarios)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "analysis failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, analysis)
}

func (h *Handler) AnalyzeDataImpact(c *gin.Context) {
	if h.simEngine == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "simulation engine not available"})
		return
	}

	var req AnalyzeDataRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	analysis, err := h.simEngine.AnalyzeDataImpact(c.Request.Context(), req.DataChanges, req.Scenarios)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "analysis failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, analysis)
}

func (h *Handler) SimulationRefresh(c *gin.Context) {
	if h.simEngine == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "simulation engine not available"})
		return
	}

	if err := h.simEngine.Refresh(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "refresh failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "refreshed"})
}

func computeChangeType(current, proposed *simulation.Result) simulation.ChangeType {
	if current.Allowed && !proposed.Allowed {
		return simulation.ChangeRevoked
	}
	if !current.Allowed && proposed.Allowed {
		return simulation.ChangeGranted
	}
	return simulation.ChangeNoChange
}

func describeDiff(change simulation.ChangeType, current, proposed *simulation.Result) string {
	switch change {
	case simulation.ChangeGranted:
		return fmt.Sprintf("权限变更: 拒绝 → 允许 (原因: %s)", current.Reason)
	case simulation.ChangeRevoked:
		return fmt.Sprintf("权限变更: 允许 → 拒绝 (原因: %s)", proposed.Reason)
	default:
		return "无权限变更"
	}
}
