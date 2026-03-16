package management

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	stateTTL          = 15 * time.Minute
	statusWaiting     = "wait"
	statusComplete    = "ok"
	authDirName        = ".cli-proxy-api"
	geminiWebPrefix    = "gemini-web-"
	geminiWebSuffix    = ".json"
	geminiWebFilePerm  = 0o600
	geminiWebDirPerm   = 0o755
)

type AuthState struct {
	Provider  string
	Status    string
	CreatedAt time.Time
}

type GeminiWebAuthFile struct {
	Provider  string    `json:"provider"`
	Email     string    `json:"email"`
	Cookie    string    `json:"cookie"`
	UserAgent string    `json:"userAgent"`
	CreatedAt time.Time `json:"createdAt"`
}

type ManagementService struct {
	mu     sync.Mutex
	states map[string]*AuthState
	log    *zap.Logger
}

func NewManagementService(log *zap.Logger) *ManagementService {
	return &ManagementService{
		states: make(map[string]*AuthState),
		log:    log,
	}
}

func (s *ManagementService) CreateState(provider string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredLocked()

	state := randomState()
	s.states[state] = &AuthState{
		Provider:  provider,
		Status:    statusWaiting,
		CreatedAt: time.Now(),
	}

	return state
}

func (s *ManagementService) GetState(state string) (*AuthState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredLocked()

	st, ok := s.states[state]
	return st, ok
}

func (s *ManagementService) MarkComplete(state string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.states[state]
	if !ok {
		return false
	}
	st.Status = statusComplete
	return true
}

func (s *ManagementService) SaveGeminiWebAuth(email, cookie, userAgent string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(home, authDirName), geminiWebDirPerm); err != nil {
		return "", fmt.Errorf("create auth dir: %w", err)
	}

	safeEmail := sanitizeFilename(email)
	filename := fmt.Sprintf("%s%s%s", geminiWebPrefix, safeEmail, geminiWebSuffix)
	path := filepath.Join(home, authDirName, filename)

	payload := GeminiWebAuthFile{
		Provider:  "gemini-web",
		Email:     email,
		Cookie:    cookie,
		UserAgent: userAgent,
		CreatedAt: time.Now(),
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal auth file: %w", err)
	}

	if err := os.WriteFile(path, data, geminiWebFilePerm); err != nil {
		return "", fmt.Errorf("write auth file: %w", err)
	}

	s.log.Info("Saved Gemini Web auth file", zap.String("path", path), zap.String("email", email))
	return path, nil
}

func (s *ManagementService) CountGeminiWebAuthFiles() (int, error) {
	paths, err := s.ListGeminiWebAuthFiles()
	if err != nil {
		return 0, err
	}
	return len(paths), nil
}

func (s *ManagementService) ListGeminiWebAuthFiles() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home dir: %w", err)
	}
	authDir := filepath.Join(home, authDirName)
	entries, err := os.ReadDir(authDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("read auth dir: %w", err)
	}

	paths := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, geminiWebPrefix) && strings.HasSuffix(name, geminiWebSuffix) {
			paths = append(paths, filepath.Join(authDir, name))
		}
	}
	return paths, nil
}

func (s *ManagementService) pruneExpiredLocked() {
	cutoff := time.Now().Add(-stateTTL)
	for key, st := range s.states {
		if st.CreatedAt.Before(cutoff) {
			delete(s.states, key)
		}
	}
}

func randomState() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("state-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func sanitizeFilename(value string) string {
	replacer := strings.NewReplacer(
		"@", "_",
		"/", "_",
		"\\", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
		" ", "_",
	)
	return replacer.Replace(value)
}
