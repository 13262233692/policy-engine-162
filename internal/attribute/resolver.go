package attribute

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"log"
)

type AttributeSource interface {
	Name() string
	Resolve(ctx context.Context, entityType string, key string, attrs map[string]interface{}) (map[string]interface{}, error)
}

type Resolver struct {
	mu      sync.RWMutex
	sources map[string]AttributeSource
	static  map[string]map[string]map[string]interface{}
}

func NewResolver() *Resolver {
	return &Resolver{
		sources: make(map[string]AttributeSource),
		static:  make(map[string]map[string]map[string]interface{}),
	}
}

func (r *Resolver) RegisterSource(source AttributeSource) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sources[source.Name()] = source
	log.Printf("[attribute-resolver] registered source: %s", source.Name())
}

func (r *Resolver) AddStaticAttributes(entityType string, entityID string, attrs map[string]interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.static[entityType] == nil {
		r.static[entityType] = make(map[string]map[string]interface{})
	}
	r.static[entityType][entityID] = attrs
}

func (r *Resolver) RemoveStaticAttributes(entityType string, entityID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.static[entityType] != nil {
		delete(r.static[entityType], entityID)
	}
}

func (r *Resolver) Resolve(ctx context.Context, entityType string, key string, inputAttrs map[string]interface{}) (map[string]interface{}, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	resolved := make(map[string]interface{})

	if staticAttrs, ok := r.static[entityType][key]; ok {
		for k, v := range staticAttrs {
			resolved[k] = v
		}
	}

	for k, v := range inputAttrs {
		resolved[k] = v
	}

	for name, source := range r.sources {
		enriched, err := source.Resolve(ctx, entityType, key, resolved)
		if err != nil {
			log.Printf("[attribute-resolver] source %s failed for %s/%s: %v", name, entityType, key, err)
			continue
		}
		for k, v := range enriched {
			if _, exists := resolved[k]; !exists {
				resolved[k] = v
			}
		}
	}

	return resolved, nil
}

func (r *Resolver) ResolveABACInput(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	entityTypes := []string{"subject", "resource", "action", "context"}

	for _, et := range entityTypes {
		raw, ok := input[et]
		if !ok {
			result[et] = map[string]interface{}{}
			continue
		}

		attrs, ok := raw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid %s attributes: expected map", et)
		}

		key := extractEntityKey(et, attrs)

		resolved, err := r.Resolve(ctx, et, key, attrs)
		if err != nil {
			return nil, fmt.Errorf("resolve %s attributes: %w", et, err)
		}

		result[et] = resolved
	}

	return result, nil
}

func extractEntityKey(entityType string, attrs map[string]interface{}) string {
	keyFields := map[string][]string{
		"subject":  {"id", "user_id", "sub", "email"},
		"resource": {"id", "resource_id", "arn", "uri"},
		"action":   {"id", "action_id", "name", "operation"},
		"context":  {"id", "request_id", "session_id"},
	}

	fields, ok := keyFields[entityType]
	if !ok {
		fields = []string{"id", "name"}
	}

	for _, f := range fields {
		if v, ok := attrs[f]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}

	return fmt.Sprintf("%s_unknown_%d", entityType, time.Now().UnixNano())
}

type StaticSource struct{}

func (s *StaticSource) Name() string { return "static" }

func (s *StaticSource) Resolve(_ context.Context, _ string, _ string, attrs map[string]interface{}) (map[string]interface{}, error) {
	return attrs, nil
}

type EnvironmentSource struct {
	EnvAttrs map[string]string
}

func NewEnvironmentSource() *EnvironmentSource {
	return &EnvironmentSource{
		EnvAttrs: make(map[string]string),
	}
}

func (e *EnvironmentSource) Name() string { return "environment" }

func (e *EnvironmentSource) Resolve(_ context.Context, entityType string, _ string, attrs map[string]interface{}) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	prefix := "ENV_"
	if entityType != "" {
		prefix = "ENV_" + strings.ToUpper(entityType) + "_"
	}

	for k, v := range e.EnvAttrs {
		if strings.HasPrefix(k, prefix) {
			attrName := strings.TrimPrefix(k, prefix)
			attrName = strings.ToLower(attrName)
			if _, exists := attrs[attrName]; !exists {
				result[attrName] = v
			}
		}
	}

	return result, nil
}
