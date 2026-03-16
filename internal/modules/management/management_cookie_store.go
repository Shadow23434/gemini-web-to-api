package management

import (
	"context"
	"errors"
	"strings"

	"gemini-web-to-api/internal/modules/providers"

	"go.uber.org/zap"
)

type ManagementCookieStore struct {
	client *providers.Client
	log    *zap.Logger
}

func NewManagementCookieStore(client *providers.Client, log *zap.Logger) *ManagementCookieStore {
	return &ManagementCookieStore{client: client, log: log}
}

func (m *ManagementCookieStore) ApplyCookieHeader(header string) error {
	cookies := parseCookieHeader(header)
	psid := cookies["__Secure-1PSID"]
	psidts := cookies["__Secure-1PSIDTS"]
	if strings.TrimSpace(psid) == "" {
		return errors.New("missing __Secure-1PSID cookie")
	}

	m.client.UpdateCookies(psid, psidts)

	if err := m.client.Init(context.Background()); err != nil {
		m.log.Warn("Gemini client init after cookie update failed", zap.Error(err))
		return err
	}

	m.log.Info("Gemini client updated with new cookies")
	return nil
}

func (m *ManagementCookieStore) ApplyUserAgent(userAgent string) error {
	if err := m.client.SetUserAgent(userAgent); err != nil {
		return err
	}
	m.log.Info("Gemini user agent updated")
	return nil
}

func parseCookieHeader(header string) map[string]string {
	values := make(map[string]string)
	parts := strings.Split(header, ";")
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		kv := strings.SplitN(item, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])
		if key == "" {
			continue
		}
		values[key] = value
	}
	return values
}
