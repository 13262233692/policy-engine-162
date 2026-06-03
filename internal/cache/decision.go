package cache

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"log"

	"github.com/policy-engine/engine/internal/opa"
)

type entry struct {
	decision  *opa.Decision
	expiresAt time.Time
}

type DecisionCache struct {
	cache       *lru.Cache[string, *entry]
	ttl         time.Duration
	mu          sync.Mutex
	hits        atomic.Int64
	misses      atomic.Int64
	evictions   atomic.Int64
}

func NewDecisionCache(size int, ttl time.Duration) (*DecisionCache, error) {
	if size <= 0 {
		size = 1024
	}

	lruCache, err := lru.New[string, *entry](size)
	if err != nil {
		return nil, fmt.Errorf("create LRU cache: %w", err)
	}

	c := &DecisionCache{
		cache: lruCache,
		ttl:   ttl,
	}

	log.Printf("[decision-cache] initialized with size=%d, ttl=%v", size, ttl)
	return c, nil
}

func (c *DecisionCache) Get(input opa.ABACInput) (*opa.Decision, bool) {
	key := c.computeKey(input)

	val, ok := c.cache.Get(key)
	if !ok {
		c.misses.Add(1)
		return nil, false
	}

	if time.Now().After(val.expiresAt) {
		c.cache.Remove(key)
		c.evictions.Add(1)
		c.misses.Add(1)
		return nil, false
	}

	c.hits.Add(1)
	return val.decision, true
}

func (c *DecisionCache) Set(input opa.ABACInput, decision *opa.Decision) {
	key := c.computeKey(input)

	ent := &entry{
		decision:  decision,
		expiresAt: time.Now().Add(c.ttl),
	}

	evicted := c.cache.Add(key, ent)
	if evicted {
		c.evictions.Add(1)
	}
}

func (c *DecisionCache) Invalidate(input opa.ABACInput) {
	key := c.computeKey(input)
	c.cache.Remove(key)
}

func (c *DecisionCache) InvalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache.Purge()
	log.Printf("[decision-cache] cache purged")
}

func (c *DecisionCache) Stats() map[string]interface{} {
	return map[string]interface{}{
		"size":      c.cache.Len(),
		"hits":      c.hits.Load(),
		"misses":    c.misses.Load(),
		"evictions": c.evictions.Load(),
		"hit_rate":  c.hitRate(),
		"ttl":       c.ttl.String(),
	}
}

func (c *DecisionCache) hitRate() float64 {
	hits := c.hits.Load()
	misses := c.misses.Load()
	total := hits + misses
	if total == 0 {
		return 0.0
	}
	return float64(hits) / float64(total)
}

func (c *DecisionCache) computeKey(input opa.ABACInput) string {
	data, err := json.Marshal(input)
	if err != nil {
		data = []byte(fmt.Sprintf("%v", input))
	}
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash[:])
}

func (c *DecisionCache) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	keys := c.cache.Keys()

	expired := 0
	for _, key := range keys {
		val, ok := c.cache.Get(key)
		if ok && now.After(val.expiresAt) {
			c.cache.Remove(key)
			expired++
		}
	}

	if expired > 0 {
		c.evictions.Add(int64(expired))
		log.Printf("[decision-cache] cleaned up %d expired entries", expired)
	}
}

func (c *DecisionCache) StartCleanup(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			c.Cleanup()
		}
	}()
	log.Printf("[decision-cache] started cleanup goroutine, interval=%v", interval)
}
