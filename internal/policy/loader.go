package policy

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"log"
)

type Policy struct {
	ID        string
	Name      string
	Content   string
	Path      string
	UpdatedAt time.Time
}

type Loader struct {
	mu         sync.RWMutex
	policies   map[string]*Policy
	policyDir  string
	watcher    *fsnotify.Watcher
	onChange   func()
	stopCh     chan struct{}
}

func NewLoader(policyDir string, onChange func()) (*Loader, error) {
	l := &Loader{
		policies:  make(map[string]*Policy),
		policyDir: policyDir,
		onChange:  onChange,
		stopCh:    make(chan struct{}),
	}

	if err := l.loadAll(); err != nil {
		return nil, fmt.Errorf("initial policy load failed: %w", err)
	}

	if err := l.startWatcher(); err != nil {
		log.Printf("[policy-loader] file watcher failed to start: %v, policies will not auto-reload", err)
	}

	return l, nil
}

func (l *Loader) loadAll() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	loaded := make(map[string]*Policy)

	err := filepath.WalkDir(l.policyDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".rego") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read policy %s: %w", path, err)
		}

		relPath, _ := filepath.Rel(l.policyDir, path)
		id := strings.TrimSuffix(relPath, filepath.Ext(relPath))
		id = strings.ReplaceAll(id, string(filepath.Separator), "/")

		info, _ := d.Info()
		var modTime time.Time
		if info != nil {
			modTime = info.ModTime()
		}

		loaded[id] = &Policy{
			ID:        id,
			Name:      d.Name(),
			Content:   string(content),
			Path:      path,
			UpdatedAt: modTime,
		}
		return nil
	})

	if err != nil {
		return err
	}

	l.policies = loaded
	log.Printf("[policy-loader] loaded %d policies from %s", len(loaded), l.policyDir)
	return nil
}

func (l *Loader) startWatcher() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	l.watcher = watcher

	if err := watcher.Add(l.policyDir); err != nil {
		watcher.Close()
		return err
	}

	filepath.WalkDir(l.policyDir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			watcher.Add(path)
		}
		return nil
	})

	go l.watchLoop()
	return nil
}

func (l *Loader) watchLoop() {
	var debounceTimer *time.Timer

	for {
		select {
		case <-l.stopCh:
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return
		case event, ok := <-l.watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Create | fsnotify.Write | fsnotify.Remove | fsnotify.Rename) {
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				debounceTimer = time.AfterFunc(500*time.Millisecond, func() {
					log.Printf("[policy-loader] detected change, reloading policies...")
					if err := l.loadAll(); err != nil {
						log.Printf("[policy-loader] reload error: %v", err)
						return
					}
					if l.onChange != nil {
						l.onChange()
					}
				})
			}
		case err, ok := <-l.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("[policy-loader] watcher error: %v", err)
		}
	}
}

func (l *Loader) Stop() {
	close(l.stopCh)
	if l.watcher != nil {
		l.watcher.Close()
	}
}

func (l *Loader) GetAll() map[string]*Policy {
	l.mu.RLock()
	defer l.mu.RUnlock()

	result := make(map[string]*Policy, len(l.policies))
	for k, v := range l.policies {
		p := *v
		result[k] = &p
	}
	return result
}

func (l *Loader) Get(id string) (*Policy, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	p, ok := l.policies[id]
	if !ok {
		return nil, false
	}
	cp := *p
	return &cp, true
}

func (l *Loader) Create(id string, content string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	dir := filepath.Join(l.policyDir, filepath.Dir(id))
	if dir != l.policyDir {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create directory: %w", err)
		}
	}

	path := filepath.Join(l.policyDir, id+".rego")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("write policy file: %w", err)
	}

	l.policies[id] = &Policy{
		ID:        id,
		Name:      filepath.Base(id) + ".rego",
		Content:   content,
		Path:      path,
		UpdatedAt: time.Now(),
	}

	log.Printf("[policy-loader] created policy: %s", id)
	return nil
}

func (l *Loader) Update(id string, content string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	p, ok := l.policies[id]
	if !ok {
		return fmt.Errorf("policy %s not found", id)
	}

	if err := os.WriteFile(p.Path, []byte(content), 0644); err != nil {
		return fmt.Errorf("write policy file: %w", err)
	}

	p.Content = content
	p.UpdatedAt = time.Now()

	log.Printf("[policy-loader] updated policy: %s", id)
	return nil
}

func (l *Loader) Delete(id string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	p, ok := l.policies[id]
	if !ok {
		return fmt.Errorf("policy %s not found", id)
	}

	if err := os.Remove(p.Path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete policy file: %w", err)
	}

	delete(l.policies, id)
	log.Printf("[policy-loader] deleted policy: %s", id)
	return nil
}

func (l *Loader) PolicyDir() string {
	return l.policyDir
}
