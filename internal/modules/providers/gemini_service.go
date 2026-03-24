package providers

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"gemini-web-to-api/internal/commons/configs"

	"github.com/imroc/req/v3"
	"go.uber.org/zap"
)

type Client struct {
	httpClient   *req.Client
	cookies      *CookieStore
	at           string
	sid          string
	buildLabel   string
	mu           sync.RWMutex // protects: at, sid, buildLabel, healthy, accountEmail, cachedModels
	healthy      bool
	accountEmail string
	log          *zap.Logger

	autoRefresh     bool
	refreshInterval time.Duration
	stopRefresh     chan struct{}
	maxRetries      int
	cachedModels    []ModelInfo
}

type CookieStore struct {
	Secure1PSID   string    `json:"__Secure-1PSID"`
	Secure1PSIDTS string    `json:"__Secure-1PSIDTS"`
	UpdatedAt     time.Time `json:"updated_at"`
	mu            sync.RWMutex
}

const (
	defaultRefreshIntervalMinutes = 30
)

type imageRequestMetadata struct {
	ConversationID string
	ResponseID     string
	ChoiceID       string
	Tools          []string
}

type imageProgressError struct {
	Message  string
	Metadata *imageRequestMetadata
}

func (e *imageProgressError) Error() string {
	if e == nil {
		return "image generation in progress"
	}
	if strings.TrimSpace(e.Message) != "" {
		return e.Message
	}
	return "image generation in progress"
}

func NewClient(cfg *configs.Config, log *zap.Logger) *Client {
	cookies := &CookieStore{
		Secure1PSID:   cfg.Gemini.Secure1PSID,
		Secure1PSIDTS: cfg.Gemini.Secure1PSIDTS,
		UpdatedAt:     time.Now(),
	}

	client := req.NewClient().
		SetTimeout(6 * time.Minute).
		SetCommonHeaders(DefaultHeaders)

	refreshIntervalMinutes := cfg.Gemini.RefreshInterval
	if refreshIntervalMinutes <= 0 {
		refreshIntervalMinutes = defaultRefreshIntervalMinutes
	}

	return &Client{
		httpClient:      client,
		cookies:         cookies,
		autoRefresh:     true,
		refreshInterval: time.Duration(refreshIntervalMinutes) * time.Minute,
		stopRefresh:     make(chan struct{}),
		maxRetries:      cfg.Gemini.MaxRetries,
		log:             log,
	}
}

func (c *Client) Init(ctx context.Context) error {
	// Clean cookies
	c.cookies.Secure1PSID = cleanCookie(c.cookies.Secure1PSID)
	configPSIDTS := cleanCookie(c.cookies.Secure1PSIDTS) // Save original config value
	c.cookies.Secure1PSIDTS = configPSIDTS

	// Check if we should use cached cookies or clear cache
	if c.cookies.Secure1PSID != "" {
		cachedTS, err := c.LoadCachedCookies()

		// If config has a new PSIDTS that differs from cache, clear cache and use config
		if configPSIDTS != "" && cachedTS != "" && configPSIDTS != cachedTS {
			_ = c.ClearCookieCache()
			// Keep using the config value (already set above)
		} else if err == nil && cachedTS != "" && configPSIDTS == "" {
			// Only use cache if config doesn't provide PSIDTS
			c.cookies.Secure1PSIDTS = cachedTS
			c.log.Info("Loaded __Secure-1PSIDTS from cache")
		}
	}

	// Obtain PSIDTS via rotation if missing
	if c.cookies.Secure1PSID != "" && c.cookies.Secure1PSIDTS == "" {
		c.log.Info("Only __Secure-1PSID provided, attempting to obtain __Secure-1PSIDTS via rotation...")
		if err := c.RotateCookies(); err != nil {
			c.log.Info("Rotation failed, proceeding with just __Secure-1PSID (might fail)", zap.String("error", err.Error()))
		} else {
			c.log.Info("Successfully obtained __Secure-1PSIDTS via rotation")
		}
	}

	// Populate cookies
	c.httpClient.SetCommonCookies(c.cookies.ToHTTPCookies()...)

	// Get SNlM0e token
	err := c.refreshSessionToken()
	if err != nil {
		c.log.Debug("Initial session token fetch failed, attempting cookie rotation", zap.Error(err))
		// Try to rotate cookies and retry
		if rotErr := c.RotateCookies(); rotErr == nil {
			c.log.Debug("Cookie rotation succeeded, retrying session token fetch")
			err = c.refreshSessionToken()
		} else {
			c.log.Debug("Cookie rotation failed", zap.Error(rotErr))
		}
	}

	if err != nil {
		return err
	}

	// Save the valid cookies to cache immediately after successful init
	_ = c.SaveCachedCookies()

	c.log.Info("✅ Gemini client initialized successfully")

	// 5. Start auto-refresh in background
	if c.autoRefresh {
		go c.startAutoRefresh()
	}

	return nil
}

func (c *Client) refreshSessionToken() error {
	// 1. Initial hit to google.com to get extra cookies (NID, etc)
	tmpClient := req.NewClient().
		SetTimeout(30 * time.Second).
		SetUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	resp1, err := tmpClient.R().Get("https://www.google.com/")
	extraCookies := ""
	if err == nil {
		parts := []string{}
		for _, ck := range resp1.Cookies() {
			parts = append(parts, fmt.Sprintf("%s=%s", ck.Name, ck.Value))
			// Also sync to main client
			c.httpClient.SetCommonCookies(ck)
		}
		if len(parts) > 0 {
			extraCookies = strings.Join(parts, "; ") + "; "
		}
	}

	// 2. Prepare full cookie string
	cookieStr := fmt.Sprintf("%s__Secure-1PSID=%s; __Secure-1PSIDTS=%s",
		extraCookies, c.cookies.Secure1PSID, c.cookies.Secure1PSIDTS)

	commonHeaders := map[string]string{
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		"Accept-Language":           "en-US,en;q=0.9",
		"Cache-Control":             "max-age=0",
		"Origin":                    "https://gemini.google.com",
		"Sec-Ch-Ua":                 `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
		"Sec-Ch-Ua-Mobile":          "?0",
		"Sec-Ch-Ua-Platform":        `"Windows"`,
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "none",
		"Sec-Fetch-User":            "?1",
		"Upgrade-Insecure-Requests": "1",
		"X-Same-Domain":             "1",
		"User-Agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	}

	hClient := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // follow redirects
		},
	}

	// Helper to merge cookies into a map to avoid duplicates
	mergeCookies := func(baseStr string, newCks []*http.Cookie) string {
		m := make(map[string]string)
		for _, part := range strings.Split(baseStr, ";") {
			p := strings.TrimSpace(part)
			if p == "" {
				continue
			}
			kv := strings.SplitN(p, "=", 2)
			if len(kv) == 2 {
				m[kv[0]] = kv[1]
			}
		}
		for _, ck := range newCks {
			m[ck.Name] = ck.Value
		}
		res := []string{}
		for k, v := range m {
			res = append(res, fmt.Sprintf("%s=%s", k, v))
		}
		return strings.Join(res, "; ")
	}

	req1, _ := http.NewRequest("GET", "https://gemini.google.com/?hl=en", nil)
	for k, v := range commonHeaders {
		req1.Header.Set(k, v)
	}
	req1.Header.Set("Cookie", cookieStr)
	resp1_direct, _ := hClient.Do(req1)
	if resp1_direct != nil {
		cookieStr = mergeCookies(cookieStr, resp1_direct.Cookies())
		for _, ck := range resp1_direct.Cookies() {
			c.httpClient.SetCommonCookies(ck)
		}
		resp1_direct.Body.Close()
	}

	// 2. The main INIT hit
	req2, _ := http.NewRequest("GET", EndpointInit+"?hl=en", nil)
	for k, v := range commonHeaders {
		req2.Header.Set(k, v)
	}
	req2.Header.Set("Sec-Fetch-Site", "same-origin")
	req2.Header.Set("Cookie", cookieStr)
	req2.Header.Set("Referer", "https://gemini.google.com/")
	req2.Header.Set("Accept-Encoding", "gzip, deflate, br")

	resp, err := hClient.Do(req2)
	if err != nil {
		return fmt.Errorf("failed to reach gemini app: %w", err)
	}
	defer resp.Body.Close()

	// Dump for debugging if it fails
	// reqDump, _ := httputil.DumpRequestOut(req2, false)
	// respDump, _ := httputil.DumpResponse(resp, false)

	var bodyReader io.ReadCloser = resp.Body
	if strings.Contains(resp.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(resp.Body)
		if err == nil {
			bodyReader = gz
			defer gz.Close()
		}
	}

	bodyBytes, _ := io.ReadAll(bodyReader)
	body := string(bodyBytes)
	accountEmail := extractGoogleAccountEmail(body)

	re := regexp.MustCompile(`"SNlM0e":"([^"]+)"`)
	matches := re.FindStringSubmatch(body)
	if len(matches) < 2 {
		reFallback := regexp.MustCompile(`\["SNlM0e","([^"]+)"\]`)
		matches = reFallback.FindStringSubmatch(body)
		if len(matches) < 2 {

			errMsg := "authentication failed: SNlM0e not found"
			if strings.Contains(body, "Sign in") || strings.Contains(body, "login") {
				errMsg = "authentication failed: cookies invalid. Please provide __Secure-1PSIDTS in addition to __Secure-1PSID"
			}

			// Log as Info to avoid stack trace for expected auth failures
			c.log.Info(errMsg)
			return fmt.Errorf("%s", errMsg)
		}
	}

	sid := extractGeminiSessionID(body)
	buildLabel := extractGeminiBuildLabel(body)

	c.mu.Lock()
	c.at = matches[1]
	c.sid = sid
	c.buildLabel = buildLabel
	c.healthy = true
	c.accountEmail = accountEmail
	c.mu.Unlock()

	if accountEmail != "" {
		c.log.Info("Authenticated Gemini account", zap.String("gmail_account", accountEmail))
	}

	// Update dynamic models from the same initialization body
	c.refreshModels(body)

	return nil
}

func extractGoogleAccountEmail(body string) string {
	emailRegexes := []*regexp.Regexp{
		regexp.MustCompile(`(?i)email&quot;:\s*&quot;([^&]+@gmail\.com)&quot;`),
		regexp.MustCompile(`(?i)"email"\s*:\s*"([^"\\s]+@gmail\.com)"`),
		regexp.MustCompile(`(?i)"identifier"\s*:\s*"([^"\\s]+@gmail\.com)"`),
		regexp.MustCompile(`(?i)([a-zA-Z0-9._%+\-]+@gmail\.com)`),
	}

	for _, re := range emailRegexes {
		matches := re.FindStringSubmatch(body)
		if len(matches) < 2 {
			continue
		}
		return strings.TrimSpace(strings.Trim(matches[1], `"'`))
	}

	return ""
}

func extractGeminiSessionID(body string) string {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`"FdrFJe":"([\d-]+)"`),
		regexp.MustCompile(`\["FdrFJe","([\d-]+)"\]`),
	}
	for _, pattern := range patterns {
		if matches := pattern.FindStringSubmatch(body); len(matches) >= 2 {
			return strings.TrimSpace(matches[1])
		}
	}
	return ""
}

func extractGeminiBuildLabel(body string) string {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`"cfb2h":"([^"]+)"`),
		regexp.MustCompile(`\["cfb2h","([^"]+)"\]`),
		regexp.MustCompile(`"bl":"([^"]+)"`),
		regexp.MustCompile(`boq_[A-Za-z0-9_-]+_[0-9]{8}\.[0-9]{2}_p[0-9]+`),
	}
	for _, pattern := range patterns {
		if matches := pattern.FindStringSubmatch(body); len(matches) >= 2 {
			return strings.TrimSpace(matches[1])
		}
		if match := pattern.FindString(body); match != "" {
			return strings.TrimSpace(match)
		}
	}
	return ""
}

func (c *Client) refreshModels(body string) {
	var newModels []ModelInfo
	now := time.Now().Unix()

	// Improved regex to find gemini model IDs even when escaped in JSON
	// Matches IDs like gemini-2.0-flash, gemini-1.5-pro, etc.
	// We look for gemini- followed by alphanumeric characters, dots, or dashes.
	modelIDRegex := regexp.MustCompile(`gemini-[a-zA-Z0-9.-]+`)
	matches := modelIDRegex.FindAllString(body, -1)

	uniqueIDs := make(map[string]bool)
	for _, id := range matches {
		// Clean up potential trailing backslashes or quotes if they were caught
		id = strings.Trim(id, `\"' `)

		// Basic validation: ensure it doesn't look like a generic string or partial ID
		if !uniqueIDs[id] && len(id) > 10 {
			uniqueIDs[id] = true
			newModels = append(newModels, inferModelInfo(id, now))
		}
	}

	c.mu.Lock()
	c.cachedModels = newModels
	c.mu.Unlock()

	if len(newModels) == 0 {
		c.log.Warn("⚠️ No models found in Gemini Web response. Please check your cookies or connection.")
	} else {
		ids := make([]string, 0, len(newModels))
		for _, m := range newModels {
			ids = append(ids, m.ID)
		}
		c.log.Info("🔄 Refreshed available models from Gemini Web", zap.Int("count", len(newModels)), zap.Strings("models", ids))
	}
}

// startAutoRefresh periodically refreshes the PSIDTS cookie
func (c *Client) startAutoRefresh() {
	ticker := time.NewTicker(c.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.log.Debug("Starting scheduled cookie refresh")
			rotateErr := c.RotateCookies()
			if rotateErr != nil {
				// Check if it's a 401/403 (cookies fully expired) — no point retrying session token
				isCookieExpired := strings.Contains(rotateErr.Error(), "status 401") ||
					strings.Contains(rotateErr.Error(), "status 403")

				if isCookieExpired {
					c.log.Error("Cookies have expired — please update GEMINI_1PSID and GEMINI_1PSIDTS in .env",
						zap.Error(rotateErr),
						zap.String("action", "Visit https://gemini.google.com → F12 → Application → Cookies"),
					)
					c.mu.Lock()
					c.healthy = false
					c.mu.Unlock()
					continue
				}

				// RotateCookies failed but NOT due to expired cookies (Google may not return new cookie every time)
				// Fallback: try to refresh the session token (SNlM0e/at) to keep client alive
				c.log.Warn("Cookie rotation failed, falling back to session token refresh", zap.Error(rotateErr))
				if sessionErr := c.refreshSessionToken(); sessionErr != nil {
					// Both methods failed — mark client as unhealthy so callers know
					c.log.Error("Session token refresh also failed, marking client unhealthy",
						zap.NamedError("rotation_error", rotateErr),
						zap.NamedError("session_error", sessionErr),
					)
					c.mu.Lock()
					c.healthy = false
					c.mu.Unlock()
				} else {
					c.log.Info("Session token refreshed successfully after rotation failure")
					// Ensure client is marked healthy since session token is valid
					c.mu.Lock()
					c.healthy = true
					c.mu.Unlock()
				}
			} else {
				// Rotation succeeded — also refresh session token to keep SNlM0e/at up to date
				if sessionErr := c.refreshSessionToken(); sessionErr != nil {
					c.log.Warn("Cookie rotated but session token refresh failed", zap.Error(sessionErr))
				} else {
					c.log.Info("Cookie and session token refreshed successfully")
				}
			}
		case <-c.stopRefresh:
			return
		}
	}
}

func (c *Client) RotateCookies() error {
	c.cookies.mu.Lock()
	defer c.cookies.mu.Unlock()

	// Prepare cookies for rotation request
	// NOTE: We access fields directly instead of using ToHTTPCookies() to avoid recursive locking (deadlock)
	parts := []string{}
	if c.cookies.Secure1PSID != "" {
		parts = append(parts, fmt.Sprintf("__Secure-1PSID=%s", c.cookies.Secure1PSID))
	}
	if c.cookies.Secure1PSIDTS != "" {
		parts = append(parts, fmt.Sprintf("__Secure-1PSIDTS=%s", c.cookies.Secure1PSIDTS))
	}
	cookieStr := strings.Join(parts, "; ")

	// Payload must be exactly this string
	strBody := `[000,"-0000000000000000000"]`
	req, _ := http.NewRequest("POST", EndpointRotateCookies, strings.NewReader(strBody))

	req.Header.Set("Content-Type", "application/json")
	// Google often blocks requests with default Go-http-client User-Agent
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Cookie", cookieStr)

	c.log.Debug("Sending rotation request", zap.String("url", EndpointRotateCookies))
	hClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := hClient.Do(req)
	if err != nil {
		// Log as Info to avoid scary stacktraces in development mode for expected auth failures
		c.log.Info("Rotation request failed (network/auth issue)", zap.String("error", err.Error()))
		return fmt.Errorf("failed to call rotation endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.log.Info("Rotation failed (likely invalid __Secure-1PSID)", zap.Int("status", resp.StatusCode))
		return fmt.Errorf("rotation failed with status %d", resp.StatusCode)
	}

	// Extract new PSIDTS from Set-Cookie headers
	found := false
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "__Secure-1PSIDTS" {
			c.cookies.Secure1PSIDTS = cookie.Value
			c.cookies.UpdatedAt = time.Now()
			found = true
			// Save the new cookie to cache immediately
			_ = c.SaveCachedCookies()
		}
		// Sync to req/v3 client for future calls
		c.httpClient.SetCommonCookies(cookie)
	}

	if found {
		c.log.Info("Cookie rotated successfully", zap.Time("updated_at", c.cookies.UpdatedAt))
		return nil
	}

	return errors.New("no new __Secure-1PSIDTS cookie received")
}

func (c *Client) GetCookies() *CookieStore {
	c.cookies.mu.RLock()
	defer c.cookies.mu.RUnlock()

	return &CookieStore{
		Secure1PSID:   c.cookies.Secure1PSID,
		Secure1PSIDTS: c.cookies.Secure1PSIDTS,
		UpdatedAt:     c.cookies.UpdatedAt,
	}
}

func (c *Client) GenerateContent(ctx context.Context, prompt string, options ...GenerateOption) (*Response, error) {
	config, at, modelInfo, err := c.prepareGenerateConfig(options...)
	if err != nil {
		return nil, err
	}
	if !modelInfo.SupportsTextGeneration {
		return nil, fmt.Errorf("model '%s' does not support text generation", config.Model)
	}

	payload, err := buildTextGeneratePayload(prompt, config.Model)
	if err != nil {
		return nil, err
	}

	return c.executeGenerationRequest(ctx, at, payload, c.parseResponse, "GenerateContent")
}

func (c *Client) GenerateImages(ctx context.Context, prompt string, options ...GenerateOption) (*Response, error) {
	config, at, modelInfo, err := c.prepareGenerateConfig(options...)
	if err != nil {
		return nil, err
	}
	if !modelInfo.SupportsImageGeneration {
		return nil, fmt.Errorf("model '%s' does not support image generation", config.Model)
	}

	payload, err := buildImageGeneratePayload(prompt, config, nil)
	if err != nil {
		return nil, err
	}

	response, err := c.executeGenerationRequest(ctx, at, payload, c.parseImageResponse, "GenerateImages")
	if err == nil {
		return response, nil
	}

	var progressErr *imageProgressError
	if !errors.As(err, &progressErr) {
		return nil, err
	}

	return c.pollImageGeneration(ctx, at, prompt, config, progressErr)
}

func (c *Client) prepareGenerateConfig(options ...GenerateOption) (*GenerateConfig, string, ModelInfo, error) {
	config := &GenerateConfig{}
	for _, opt := range options {
		opt(config)
	}

	c.mu.RLock()
	if config.Model == "" || config.Model == "gemini-pro" {
		if len(c.cachedModels) > 0 {
			config.Model = c.cachedModels[0].ID
		}
	}

	var modelInfo ModelInfo
	found := false
	for _, m := range c.cachedModels {
		if m.ID == config.Model {
			modelInfo = m
			found = true
			break
		}
	}
	at := c.at
	c.mu.RUnlock()

	if !found && config.Model != "" {
		return nil, "", ModelInfo{}, fmt.Errorf("model '%s' is not supported or not available. Available models: %v", config.Model, c.ListModelsIDs())
	}
	if at == "" {
		return nil, "", ModelInfo{}, errors.New("client not initialized")
	}

	return config, at, modelInfo, nil
}

func buildTextGeneratePayload(prompt, model string) (map[string]string, error) {
	inner := []interface{}{
		[]interface{}{prompt},
		nil,
		nil,
		model,
	}

	return buildGenerationFormData(inner)
}

func buildImageGeneratePayload(prompt string, config *GenerateConfig, metadata *imageRequestMetadata) (map[string]string, error) {
	hasMetadata := metadata != nil && (metadata.ConversationID != "" || metadata.ResponseID != "" || metadata.ChoiceID != "")
	if !hasMetadata {
		return buildTextGeneratePayload(prompt, config.Model)
	}

	conversation := []interface{}{nil, nil, nil, nil, nil, []interface{}{}}
	if metadata != nil {
		if metadata.ConversationID != "" {
			conversation[0] = metadata.ConversationID
		}
		if metadata.ResponseID != "" {
			conversation[1] = metadata.ResponseID
		}
		if metadata.ChoiceID != "" {
			conversation[2] = metadata.ChoiceID
		}
	}

	inner := []interface{}{
		[]interface{}{prompt, 0, nil, []interface{}{}, nil, nil, 0},
		[]interface{}{"en"},
		conversation,
		nil,
		nil,
		nil,
		[]interface{}{1},
		0,
		[]interface{}{},
		[]interface{}{},
		1,
		0,
	}

	return buildGenerationFormData(inner)
}

func buildGenerationFormData(inner []interface{}) (map[string]string, error) {
	innerJSON, err := json.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal inner payload: %w", err)
	}

	outer := []interface{}{nil, string(innerJSON)}
	outerJSON, err := json.Marshal(outer)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal outer payload: %w", err)
	}

	return map[string]string{
		"f.req": string(outerJSON),
	}, nil
}

func extractModelIDFromFormData(formData map[string]string) string {
	payload, ok := formData["f.req"]
	if !ok || strings.TrimSpace(payload) == "" {
		return ""
	}

	var outer []interface{}
	if err := json.Unmarshal([]byte(payload), &outer); err != nil || len(outer) < 2 {
		return ""
	}
	innerString, ok := outer[1].(string)
	if !ok || strings.TrimSpace(innerString) == "" {
		return ""
	}

	var inner []interface{}
	if err := json.Unmarshal([]byte(innerString), &inner); err != nil || len(inner) == 0 {
		return ""
	}

	for i := len(inner) - 1; i >= 0; i-- {
		if model, ok := inner[i].(string); ok && strings.HasPrefix(strings.ToLower(strings.TrimSpace(model)), "gemini-") {
			return strings.TrimSpace(model)
		}
	}
	return ""
}

func geminiModelHeaderValue(modelID string, cachedModels []ModelInfo) string {
	modelID = strings.ToLower(strings.TrimSpace(modelID))
	if modelID == "" {
		return ""
	}
	if strings.Contains(modelID, "image") {
		return `[1,null,null,null,"e6fa609c3fa255c0",null,null,null,[4]]`
	}
	for _, model := range cachedModels {
		if strings.EqualFold(strings.TrimSpace(model.ID), modelID) && model.SupportsImageGeneration {
			return `[1,null,null,null,"e6fa609c3fa255c0",null,null,null,[4]]`
		}
	}
	return ""
}

func (c *Client) pollImageGeneration(ctx context.Context, at, prompt string, config *GenerateConfig, progress *imageProgressError) (*Response, error) {
	metadata := &imageRequestMetadata{}
	if progress != nil && progress.Metadata != nil {
		metadata = progress.Metadata
	}

	var lastErr error = progress
	for attempt := 1; attempt <= 120; attempt++ {
		wait := 2 * time.Second
		if attempt > 10 {
			wait = 5 * time.Second
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}

		payload, err := buildImageGeneratePayload(prompt, config, metadata)
		if err != nil {
			return nil, err
		}

		response, err := c.executeGenerationRequest(ctx, at, payload, c.parseImageResponse, "GenerateImagesPoll")
		if err == nil {
			if response.Metadata != nil {
				mergeImageResponseMetadata(metadata, response.Metadata)
			}
			return response, nil
		}

		var nextProgress *imageProgressError
		if errors.As(err, &nextProgress) {
			lastErr = err
			if nextProgress != nil && nextProgress.Metadata != nil {
				mergeImageRequestMetadata(metadata, nextProgress.Metadata)
			}
			continue
		}

		return nil, err
	}

	if lastErr != nil {
		return nil, fmt.Errorf("timed out waiting for Gemini image generation: %w", lastErr)
	}
	return nil, fmt.Errorf("timed out waiting for Gemini image generation")
}

func mergeImageRequestMetadata(dst, src *imageRequestMetadata) {
	if dst == nil || src == nil {
		return
	}
	if dst.ConversationID == "" {
		dst.ConversationID = src.ConversationID
	}
	if dst.ResponseID == "" {
		dst.ResponseID = src.ResponseID
	}
	if dst.ChoiceID == "" {
		dst.ChoiceID = src.ChoiceID
	}
	seen := map[string]bool{}
	for _, tool := range dst.Tools {
		seen[tool] = true
	}
	for _, tool := range src.Tools {
		if !seen[tool] {
			dst.Tools = append(dst.Tools, tool)
			seen[tool] = true
		}
	}
}

func mergeImageResponseMetadata(dst *imageRequestMetadata, metadata map[string]any) {
	if dst == nil || metadata == nil {
		return
	}
	mergeImageRequestMetadata(dst, &imageRequestMetadata{
		ConversationID: stringMetadataValue(metadata, "cid"),
		ResponseID:     stringMetadataValue(metadata, "rid"),
		ChoiceID:       stringMetadataValue(metadata, "rcid"),
		Tools:          stringSliceMetadataValue(metadata, "tools"),
	})
}

func stringMetadataValue(metadata map[string]any, key string) string {
	value, _ := metadata[key].(string)
	return strings.TrimSpace(value)
}

func stringSliceMetadataValue(metadata map[string]any, key string) []string {
	raw, ok := metadata[key].([]string)
	if ok {
		return raw
	}
	items, ok := metadata[key].([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if ok && strings.TrimSpace(text) != "" {
			result = append(result, strings.TrimSpace(text))
		}
	}
	return result
}

func (c *Client) executeGenerationRequest(ctx context.Context, at string, formData map[string]string, parser func(string) (*Response, error), operation string) (*Response, error) {
	formData["at"] = at

	c.mu.RLock()
	sid := c.sid
	buildLabel := c.buildLabel
	cachedModels := append([]ModelInfo(nil), c.cachedModels...)
	c.mu.RUnlock()

	maxAttempts := c.maxRetries
	if maxAttempts <= 0 {
		maxAttempts = 1
	}

	totalStart := time.Now()
	var lastErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			backoff := time.Duration(1<<uint(attempt-2)) * time.Second
			c.log.Warn("Retrying generation request",
				zap.String("operation", operation),
				zap.Int("attempt", attempt),
				zap.Int("max_attempts", maxAttempts),
				zap.Duration("backoff", backoff),
				zap.Error(lastErr),
			)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		httpStart := time.Now()
		request := c.httpClient.R().
			SetContext(ctx).
			SetFormData(formData).
			SetQueryParam("at", at)
		if headerValue := geminiModelHeaderValue(extractModelIDFromFormData(formData), cachedModels); headerValue != "" {
			request.SetHeader("x-goog-ext-525001261-jspb", headerValue)
		}
		if strings.TrimSpace(buildLabel) != "" {
			request.SetQueryParam("bl", buildLabel)
		}
		if strings.TrimSpace(sid) != "" {
			request.SetQueryParam("f.sid", sid)
		}
		request.SetQueryParam("hl", "en")
		request.SetQueryParam("rt", "c")
		request.SetQueryParam("_reqid", strconv.FormatInt(time.Now().UnixMilli()%9000+1000, 10))

		resp, err := request.Post(EndpointGenerate)

		httpDuration := time.Since(httpStart)
		if err != nil {
			c.log.Warn("Generate request failed, will retry",
				zap.String("operation", operation),
				zap.Error(err),
				zap.Duration("http_duration", httpDuration),
				zap.Int("attempt", attempt),
			)
			lastErr = err
			continue
		}

		if resp.StatusCode != http.StatusOK {
			body := resp.String()
			sample := body
			if len(sample) > 2000 {
				sample = sample[:2000]
			}
			c.log.Warn("Generation request returned non-200",
				zap.String("operation", operation),
				zap.Int("status", resp.StatusCode),
				zap.Int("attempt", attempt),
				zap.Int("response_bytes", len(body)),
				zap.String("response_sample", sample),
				zap.Any("request_form_data", formData),
			)
			lastErr = fmt.Errorf("generate failed with status: %d: %s", resp.StatusCode, sample)
			if resp.StatusCode >= 500 {
				c.log.Warn("Server error, will retry",
					zap.String("operation", operation),
					zap.Int("status", resp.StatusCode),
					zap.Int("attempt", attempt),
				)
				continue
			}
			return nil, lastErr
		}

		body := resp.String()
		parseStart := time.Now()
		result, parseErr := parser(body)
		parseDuration := time.Since(parseStart)
		if parseErr != nil {
			var progressErr *imageProgressError
			if errors.As(parseErr, &progressErr) {
				return nil, parseErr
			}
			lastErr = parseErr
			c.log.Warn("Failed to parse response, will retry",
				zap.String("operation", operation),
				zap.Error(parseErr),
				zap.Int("attempt", attempt),
			)
			continue
		}

		c.log.Debug("Generation request timing",
			zap.String("operation", operation),
			zap.Duration("gemini_server_rtt", httpDuration),
			zap.Duration("parse_duration", parseDuration),
			zap.Duration("total_duration", time.Since(totalStart)),
			zap.Int("attempt", attempt),
			zap.Int("response_bytes", len(body)),
		)

		if attempt > 1 {
			c.log.Info("Generation request succeeded after retry",
				zap.String("operation", operation),
				zap.Int("attempt", attempt),
			)
		}
		return result, nil
	}

	c.log.Error("Generation request failed after all attempts",
		zap.String("operation", operation),
		zap.Int("attempts", maxAttempts),
		zap.Error(lastErr),
	)
	return nil, fmt.Errorf("after %d attempts: %w", maxAttempts, lastErr)
}

func (c *Client) StartChat(options ...ChatOption) ChatSession {
	config := &ChatConfig{}
	for _, opt := range options {
		opt(config)
	}

	c.mu.RLock()
	if config.Model == "" || config.Model == "gemini-pro" {
		if len(c.cachedModels) > 0 {
			config.Model = c.cachedModels[0].ID
		}
	}
	c.mu.RUnlock()

	return &GeminiChatSession{
		client:   c,
		model:    config.Model,
		metadata: config.Metadata,
		history:  []Message{},
	}
}

func (c *Client) Close() error {
	close(c.stopRefresh)
	c.mu.Lock()
	c.healthy = false
	c.mu.Unlock()
	return nil
}

func (c *Client) GetName() string {
	return "gemini"
}

func (c *Client) IsHealthy() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.healthy
}

func (c *Client) ListModels() []ModelInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.cachedModels) == 0 {
		return []ModelInfo{}
	}

	return c.cachedModels
}

func (c *Client) ListModelsIDs() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	ids := make([]string, 0, len(c.cachedModels))
	for _, m := range c.cachedModels {
		ids = append(ids, m.ID)
	}
	return ids
}

func (c *Client) GetModelInfo(modelID string) (ModelInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, m := range c.cachedModels {
		if m.ID == modelID {
			return m, true
		}
	}

	return ModelInfo{}, false
}

// parseResponse parses Gemini's response format
func (c *Client) parseResponse(text string) (*Response, error) {
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		line = strings.TrimPrefix(line, ")]}'")

		var root []interface{}
		if err := json.Unmarshal([]byte(line), &root); err != nil {
			continue
		}

		for _, item := range root {
			itemArray, ok := item.([]interface{})
			if !ok || len(itemArray) < 3 {
				continue
			}

			payloadStr, ok := itemArray[2].(string)
			if !ok {
				continue
			}

			payload, err := parsePayloadString(payloadStr)
			if err != nil {
				continue
			}

			if response, ok := parseTextResponsePayload(payload); ok {
				return response, nil
			}
		}
	}

	sample := text
	if len(sample) > 500 {
		sample = sample[:500]
	}
	return nil, fmt.Errorf("failed to parse response. Sample: %s", sample)
}

func (c *Client) parseImageResponse(text string) (*Response, error) {
	lines := strings.Split(text, "\n")
	var pending *imageProgressError
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		line = strings.TrimPrefix(line, ")]}'")

		var root []interface{}
		if err := json.Unmarshal([]byte(line), &root); err != nil {
			continue
		}

		for _, item := range root {
			itemArray, ok := item.([]interface{})
			if !ok {
				continue
			}
			if looksLikePendingImageFrame(itemArray) {
				if pending == nil {
					pending = &imageProgressError{Message: "image generation in progress"}
				}
				continue
			}
			if len(itemArray) < 3 {
				continue
			}

			payloadStr, ok := itemArray[2].(string)
			if !ok {
				continue
			}

			payload, err := parsePayloadString(payloadStr)
			if err != nil {
				continue
			}

			if response, ok := parseImageResponsePayload(payload); ok {
				return response, nil
			}
			if progress := parseImageProgressPayload(payload); progress != nil {
				if pending == nil {
					pending = progress
				} else {
					if pending.Metadata == nil {
						pending.Metadata = progress.Metadata
					} else if progress.Metadata != nil {
						mergeImageRequestMetadata(pending.Metadata, progress.Metadata)
					}
				}
			}
		}
	}
	if pending != nil {
		return nil, pending
	}

	if c.log != nil {
		snippet := text
		if len(snippet) > 20000 {
			snippet = snippet[:20000]
		}
		lower := strings.ToLower(text)
		c.log.Debug("Failed to parse image response payload",
			zap.Int("response_bytes", len(text)),
			zap.Bool("contains_googleusercontent", strings.Contains(lower, "googleusercontent")),
			zap.Bool("contains_data_uri", strings.Contains(lower, "data:image/")),
			zap.String("response_snippet", snippet),
		)
	}

	sample := text
	if len(sample) > 500 {
		sample = sample[:500]
	}
	return nil, fmt.Errorf("failed to parse image response. Sample: %s", sample)
}

func parsePayloadString(payloadStr string) ([]interface{}, error) {
	var payloadAny interface{}
	if err := json.Unmarshal([]byte(payloadStr), &payloadAny); err != nil {
		return nil, err
	}
	return normalizePayloadValue(payloadAny)
}

func normalizePayloadValue(payloadAny interface{}) ([]interface{}, error) {
	switch typed := payloadAny.(type) {
	case []interface{}:
		return typed, nil
	case map[string]interface{}:
		return []interface{}{typed}, nil
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return nil, fmt.Errorf("empty payload string")
		}
		if strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "{") {
			var nestedAny interface{}
			if err := json.Unmarshal([]byte(trimmed), &nestedAny); err == nil {
				return normalizePayloadValue(nestedAny)
			}
		}
		return []interface{}{trimmed}, nil
	default:
		return []interface{}{payloadAny}, nil
	}
}

func parseTextResponsePayload(payload []interface{}) (*Response, bool) {
	if len(payload) <= 4 {
		return nil, false
	}

	candidates, ok := payload[4].([]interface{})
	if !ok || len(candidates) == 0 {
		return nil, false
	}

	firstCandidate, ok := candidates[0].([]interface{})
	if !ok || len(firstCandidate) < 2 {
		return nil, false
	}

	contentParts, ok := firstCandidate[1].([]interface{})
	if !ok || len(contentParts) == 0 {
		return nil, false
	}

	resText, ok := contentParts[0].(string)
	if !ok {
		return nil, false
	}

	var cid, rid, rcid string
	if len(firstCandidate) > 0 {
		if id, ok := firstCandidate[0].(string); ok {
			rcid = id
		}
	}
	if len(payload) > 1 {
		if id, ok := payload[1].(string); ok {
			cid = id
		}
	}

	if len(payload) > 2 {
		if id, ok := payload[2].(string); ok {
			rid = id
		}
	}

	return &Response{
		Text: resText,
		Metadata: map[string]any{
			"cid":  cid,
			"rid":  rid,
			"rcid": rcid,
		},
	}, true
}

func parseImageResponsePayload(payload []interface{}) (*Response, bool) {
	images := extractImagesFromValue(payload)
	if len(images) == 0 {
		images = extractImagesFromGeminiPayload(payload)
	}
	if len(images) == 0 {
		images = extractImagesFromJSONStringNodes(payload)
	}
	if len(images) == 0 {
		return nil, false
	}

	response := &Response{Images: images}
	if text, ok := extractFirstString(payload, map[string]bool{}); ok {
		response.Text = text
	}
	if metadata := extractImageRequestMetadata(payload); metadata != nil {
		response.Metadata = map[string]any{
			"cid":   metadata.ConversationID,
			"rid":   metadata.ResponseID,
			"rcid":  metadata.ChoiceID,
			"tools": metadata.Tools,
		}
	}
	return response, true
}

func parseImageProgressPayload(payload []interface{}) *imageProgressError {
	metadata := extractImageRequestMetadata(payload)
	message, hasProgress := extractImageProgressMessage(payload)
	if !hasProgress && metadata == nil && !looksLikePendingImageFrame(payload) {
		return nil
	}
	if strings.TrimSpace(message) == "" {
		message = "image generation in progress"
	}
	return &imageProgressError{
		Message:  message,
		Metadata: metadata,
	}
}

func looksLikePendingImageFrame(payload []interface{}) bool {
	if len(payload) == 0 {
		return false
	}
	if event, ok := payload[0].(string); ok && event == "wrb.fr" {
		if len(payload) >= 6 {
			if marker, ok := payload[5].([]interface{}); ok && len(marker) == 1 {
				if code, ok := marker[0].(float64); ok && int(code) == 13 {
					return true
				}
			}
		}
		if len(payload) >= 2 {
			if status, ok := payload[1].([]interface{}); ok && len(status) == 0 {
				return true
			}
		}
	}
	for _, item := range payload {
		arr, ok := item.([]interface{})
		if !ok || len(arr) == 0 {
			continue
		}
		event, ok := arr[0].(string)
		if !ok || event != "wrb.fr" {
			continue
		}
		if len(arr) >= 6 {
			if marker, ok := arr[5].([]interface{}); ok && len(marker) == 1 {
				if code, ok := marker[0].(float64); ok && int(code) == 13 {
					return true
				}
			}
		}
		if len(arr) >= 2 {
			if status, ok := arr[1].([]interface{}); ok && len(status) == 0 {
				return true
			}
		}
	}
	return false
}

func extractImagesFromJSONStringNodes(payload []interface{}) []Image {
	seen := map[string]bool{}
	images := make([]Image, 0)

	walkValue(payload, func(node interface{}) {
		str, ok := node.(string)
		if !ok {
			return
		}
		trimmed := strings.TrimSpace(str)
		if trimmed == "" {
			return
		}
		if !(strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "{")) {
			return
		}

		var nestedAny interface{}
		if err := json.Unmarshal([]byte(trimmed), &nestedAny); err != nil {
			return
		}
		nestedImages := extractImagesFromValue(nestedAny)
		if len(nestedImages) == 0 {
			nestedImages = extractImagesFromGeminiValue(nestedAny)
		}
		for _, img := range nestedImages {
			key := img.URL + "|" + img.B64JSON
			if !seen[key] {
				seen[key] = true
				images = append(images, img)
			}
		}
	})

	return images
}

func extractImagesFromValue(value interface{}) []Image {
	seen := map[string]bool{}
	var images []Image
	walkValue(value, func(node interface{}) {
		switch typed := node.(type) {
		case string:
			if image := imageFromString(typed); image != nil {
				key := image.URL + "|" + image.B64JSON
				if !seen[key] {
					seen[key] = true
					images = append(images, *image)
				}
			}
		case map[string]interface{}:
			if image := imageFromMap(typed); image != nil {
				key := image.URL + "|" + image.B64JSON
				if !seen[key] {
					seen[key] = true
					images = append(images, *image)
				}
			}
		}
	})
	return images
}

func extractImagesFromGeminiPayload(payload []interface{}) []Image {
	if len(payload) <= 4 {
		return extractImagesFromGeminiValue(payload)
	}

	candidates, ok := payload[4].([]interface{})
	if !ok || len(candidates) == 0 {
		return extractImagesFromGeminiValue(payload)
	}

	seen := map[string]bool{}
	images := make([]Image, 0)
	for _, candidateRaw := range candidates {
		candidate, ok := candidateRaw.([]interface{})
		if !ok || len(candidate) <= 12 {
			continue
		}

		candidate12 := candidate[12]
		candidateMap, ok := candidate12.(map[string]interface{})
		if !ok {
			continue
		}

		raw7, ok := candidateMap["7"]
		if !ok {
			continue
		}
		arr7, ok := raw7.([]interface{})
		if !ok || len(arr7) <= 0 {
			continue
		}

		raw0, ok := arr7[0].([]interface{})
		if !ok {
			continue
		}

		for _, imageRaw := range raw0 {
			imageArr, ok := imageRaw.([]interface{})
			if !ok || len(imageArr) <= 3 {
				continue
			}

			url, _ := extractNestedString(imageArr, 0, 3, 3)
			if url == "" {
				continue
			}

			img := Image{URL: url}
			if titleIndex, ok := extractNestedFloat(imageArr, 3, 6); ok {
				img.Title = "[GeneratedImage " + strconv.Itoa(int(titleIndex)) + "]"
			}

			if alt, ok := extractNestedString(imageArr, 3, 5, 0); ok {
				img.AltText = alt
			}

			key := img.URL + "|" + img.B64JSON
			if !seen[key] {
				seen[key] = true
				images = append(images, img)
			}
		}
	}

	if len(images) == 0 {
		return extractImagesFromGeminiValue(payload)
	}

	return images
}

func extractImagesFromGeminiValue(value interface{}) []Image {
	seen := map[string]bool{}
	images := make([]Image, 0)

	walkValue(value, func(node interface{}) {
		arr, ok := node.([]interface{})
		if !ok {
			return
		}
		if len(arr) < 4 {
			return
		}

		url, ok := extractNestedString(arr, 0, 3, 3)
		if !ok || strings.TrimSpace(url) == "" {
			url, ok = extractNestedString(arr, 0, 3, 2)
			if !ok || strings.TrimSpace(url) == "" {
				return
			}
		}

		if !(strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "data:image/")) {
			return
		}

		img := Image{URL: strings.TrimSpace(url)}
		if titleIndex, ok := extractNestedFloat(arr, 3, 6); ok {
			img.Title = "[GeneratedImage " + strconv.Itoa(int(titleIndex)) + "]"
		}
		if alt, ok := extractNestedString(arr, 3, 5, 0); ok {
			img.AltText = alt
		}

		key := img.URL + "|" + img.B64JSON
		if !seen[key] {
			seen[key] = true
			images = append(images, img)
		}
	})

	return images
}

func extractNestedString(value interface{}, path ...int) (string, bool) {
	current := value
	for _, idx := range path {
		arr, ok := current.([]interface{})
		if !ok || idx < 0 || idx >= len(arr) {
			return "", false
		}
		current = arr[idx]
	}

	str, ok := current.(string)
	if !ok {
		return "", false
	}

	str = strings.TrimSpace(str)
	if str == "" {
		return "", false
	}

	return str, true
}

func extractNestedFloat(value interface{}, path ...int) (float64, bool) {
	current := value
	for _, idx := range path {
		arr, ok := current.([]interface{})
		if !ok || idx < 0 || idx >= len(arr) {
			return 0, false
		}
		current = arr[idx]
	}

	num, ok := current.(float64)
	if !ok {
		return 0, false
	}

	return num, true
}

func extractImageProgressMessage(value interface{}) (string, bool) {
	var message string
	found := false
	walkValue(value, func(node interface{}) {
		if found {
			return
		}
		text, ok := node.(string)
		if !ok {
			return
		}
		trimmed := strings.TrimSpace(text)
		if trimmed == "" {
			return
		}
		lower := strings.ToLower(trimmed)
		if strings.Contains(lower, "creating your image") || strings.Contains(lower, "data_analysis_tool") {
			message = trimmed
			found = true
		}
	})
	return message, found
}

func extractImageRequestMetadata(value interface{}) *imageRequestMetadata {
	metadata := &imageRequestMetadata{}
	seenTools := map[string]bool{}

	if payload, ok := value.([]interface{}); ok {
		if len(payload) > 1 {
			if ids, ok := payload[1].([]interface{}); ok {
				if len(ids) > 0 {
					if cid, ok := ids[0].(string); ok && strings.TrimSpace(cid) != "" {
						metadata.ConversationID = strings.TrimSpace(cid)
					}
				}
				if len(ids) > 1 {
					if rid, ok := ids[1].(string); ok && strings.TrimSpace(rid) != "" {
						metadata.ResponseID = strings.TrimSpace(rid)
					}
				}
			}
		}
		if len(payload) > 4 {
			if candidates, ok := payload[4].([]interface{}); ok && len(candidates) > 0 {
				if firstCandidate, ok := candidates[0].([]interface{}); ok && len(firstCandidate) > 0 {
					if choiceID, ok := firstCandidate[0].(string); ok && strings.TrimSpace(choiceID) != "" {
						metadata.ChoiceID = strings.TrimSpace(choiceID)
					}
				}
			}
		}
	}

	walkValue(value, func(node interface{}) {
		switch typed := node.(type) {
		case string:
			trimmed := strings.TrimSpace(typed)
			if strings.HasPrefix(trimmed, "c_") && metadata.ConversationID == "" {
				metadata.ConversationID = trimmed
			}
			if strings.HasPrefix(trimmed, "r_") {
				if metadata.ResponseID == "" {
					metadata.ResponseID = trimmed
					return
				}
				if metadata.ChoiceID == "" && trimmed != metadata.ResponseID {
					metadata.ChoiceID = trimmed
					return
				}
			}
			if trimmed == "data_analysis_tool" && !seenTools[trimmed] {
				metadata.Tools = append(metadata.Tools, trimmed)
				seenTools[trimmed] = true
			}
		case []interface{}:
			if len(typed) == 0 {
				return
			}
			first, ok := typed[0].(string)
			if !ok {
				return
			}
			trimmed := strings.TrimSpace(first)
			if trimmed == "data_analysis_tool" && !seenTools[trimmed] {
				metadata.Tools = append(metadata.Tools, trimmed)
				seenTools[trimmed] = true
			}
		}
	})

	if metadata.ConversationID == "" && metadata.ResponseID == "" && metadata.ChoiceID == "" && len(metadata.Tools) == 0 {
		return nil
	}
	return metadata
}

func walkValue(value interface{}, visit func(interface{})) {
	visit(value)
	switch typed := value.(type) {
	case []interface{}:
		for _, item := range typed {
			walkValue(item, visit)
		}
	case map[string]interface{}:
		for _, item := range typed {
			walkValue(item, visit)
		}
	}
}

func imageFromString(value string) *Image {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		if strings.Contains(lower, ".png") || strings.Contains(lower, ".jpg") || strings.Contains(lower, ".jpeg") || strings.Contains(lower, ".webp") || strings.Contains(lower, "image") || strings.Contains(lower, "googleusercontent") {
			return &Image{URL: trimmed}
		}
	}
	if looksLikeBase64Image(trimmed) {
		return &Image{B64JSON: trimmed, MimeType: detectMimeTypeFromBase64(trimmed)}
	}
	return nil
}

func imageFromMap(value map[string]interface{}) *Image {
	image := &Image{}

	if url, ok := firstStringMapValue(value, "url", "uri", "image_url", "src"); ok {
		image.URL = url
	}
	if b64, ok := firstStringMapValue(value, "b64_json", "data", "image_bytes", "inline_data"); ok && looksLikeBase64Image(b64) {
		image.B64JSON = b64
	}
	if mimeType, ok := firstStringMapValue(value, "mime_type", "mimeType", "content_type"); ok {
		image.MimeType = mimeType
	}
	if title, ok := firstStringMapValue(value, "title", "label"); ok {
		image.Title = title
	}
	if altText, ok := firstStringMapValue(value, "alt", "alt_text", "altText"); ok {
		image.AltText = altText
	}

	if image.URL == "" && image.B64JSON == "" {
		return nil
	}
	if image.MimeType == "" && image.B64JSON != "" {
		image.MimeType = detectMimeTypeFromBase64(image.B64JSON)
	}
	return image
}

func firstStringMapValue(value map[string]interface{}, keys ...string) (string, bool) {
	for _, key := range keys {
		raw, ok := value[key]
		if !ok {
			continue
		}
		if str, ok := raw.(string); ok && strings.TrimSpace(str) != "" {
			return strings.TrimSpace(str), true
		}
	}
	return "", false
}

func looksLikeBase64Image(value string) bool {
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(trimmed, "data:image/") {
		return true
	}
	if len(trimmed) < 128 {
		return false
	}
	matched, _ := regexp.MatchString(`^[A-Za-z0-9+/=_-]+$`, trimmed)
	return matched
}

func detectMimeTypeFromBase64(value string) string {
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(trimmed, "data:image/") {
		parts := strings.SplitN(trimmed, ";", 2)
		if len(parts) > 0 {
			return strings.TrimPrefix(parts[0], "data:")
		}
	}
	return "image/png"
}

func extractFirstString(value interface{}, visited map[string]bool) (string, bool) {
	switch typed := value.(type) {
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" || imageFromString(trimmed) != nil {
			return "", false
		}
		return trimmed, true
	case []interface{}:
		for _, item := range typed {
			if result, ok := extractFirstString(item, visited); ok {
				return result, true
			}
		}
	case map[string]interface{}:
		for key, item := range typed {
			if visited[key] {
				continue
			}
			visited[key] = true
			if result, ok := extractFirstString(item, visited); ok {
				return result, true
			}
		}
	}
	return "", false
}

func (cs *CookieStore) ToHTTPCookies() []*http.Cookie {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	cookies := []*http.Cookie{}
	domain := ".google.com"

	if cs.Secure1PSID != "" {
		cookies = append(cookies, &http.Cookie{
			Name:     "__Secure-1PSID",
			Value:    cleanCookie(cs.Secure1PSID),
			Domain:   domain,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteNoneMode,
		})
	}
	if cs.Secure1PSIDTS != "" {
		cookies = append(cookies, &http.Cookie{
			Name:     "__Secure-1PSIDTS",
			Value:    cleanCookie(cs.Secure1PSIDTS),
			Domain:   domain,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteNoneMode,
		})
	}
	return cookies
}

func cleanCookie(v string) string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, "\"")
	v = strings.Trim(v, "'")
	v = strings.TrimSuffix(v, ";")
	return v
}

// LoadCachedCookies attempts to read the saved 1PSIDTS from disk
func (c *Client) LoadCachedCookies() (string, error) {
	if c.cookies.Secure1PSID == "" {
		return "", errors.New("no PSID available")
	}

	hash := sha256.Sum256([]byte(c.cookies.Secure1PSID))
	filename := filepath.Join(".cookies", hex.EncodeToString(hash[:])+".txt")

	data, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}

	ts := strings.TrimSpace(string(data))
	if ts == "" {
		return "", errors.New("empty cache file")
	}
	return ts, nil
}

// SaveCachedCookies writes the current 1PSIDTS to disk
func (c *Client) SaveCachedCookies() error {
	if c.cookies.Secure1PSID == "" || c.cookies.Secure1PSIDTS == "" {
		return nil
	}

	// Create directory if not exists
	if err := os.MkdirAll(".cookies", 0755); err != nil {
		return err
	}

	hash := sha256.Sum256([]byte(c.cookies.Secure1PSID))
	filename := filepath.Join(".cookies", hex.EncodeToString(hash[:])+".txt")

	err := os.WriteFile(filename, []byte(c.cookies.Secure1PSIDTS), 0600)
	if err == nil {
		c.log.Debug("Saved __Secure-1PSIDTS to local cache for future use", zap.String("file", filename))
	} else {
		c.log.Warn("Failed to save cookies to cache", zap.String("file", filename), zap.Error(err))
	}
	return err
}

// ClearCookieCache deletes the cached cookie file for the current PSID
func (c *Client) ClearCookieCache() error {
	if c.cookies.Secure1PSID == "" {
		return nil
	}

	hash := sha256.Sum256([]byte(c.cookies.Secure1PSID))
	filename := filepath.Join(".cookies", hex.EncodeToString(hash[:])+".txt")

	err := os.Remove(filename)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

const (
	EndpointGoogle        = "https://www.google.com"
	EndpointInit          = "https://gemini.google.com/app"
	EndpointGenerate      = "https://gemini.google.com/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate"
	EndpointRotateCookies = "https://accounts.google.com/RotateCookies"
	EndpointBatchExec     = "https://gemini.google.com/_/BardChatUi/data/batchexecute"
)

var DefaultHeaders = map[string]string{
	"Content-Type":  "application/x-www-form-urlencoded;charset=utf-8",
	"Origin":        "https://gemini.google.com",
	"Referer":       "https://gemini.google.com/",
	"User-Agent":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"X-Same-Domain": "1",
}
