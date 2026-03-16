package management

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"
)

type ManagementController struct {
	svc    *ManagementService
	cookies *ManagementCookieStore
	log    *zap.Logger
}

func NewManagementController(svc *ManagementService, cookies *ManagementCookieStore, log *zap.Logger) *ManagementController {
	return &ManagementController{svc: svc, cookies: cookies, log: log}
}

func RegisterRoutes(app *fiber.App, c *ManagementController) {
	group := app.Group("/v0/management")
	group.Get("/gemini-web-auth-url", c.HandleGeminiWebAuthURL)
	group.Get("/get-auth-status", c.HandleGetAuthStatus)
	group.Get("/gemini-web-auth", c.HandleGeminiWebAuthPage)
	group.Post("/gemini-web-auth-complete", c.HandleGeminiWebAuthComplete)
}

func (c *ManagementController) HandleGeminiWebAuthURL(ctx fiber.Ctx) error {
	state := c.svc.CreateState("gemini-web")
	base := fmt.Sprintf("%s://%s", ctx.Protocol(), ctx.Hostname())
	if port := ctx.Port(); port != "" {
		base = fmt.Sprintf("%s:%s", base, port)
	}

	authURL := fmt.Sprintf("%s/v0/management/gemini-web-auth?state=%s", base, url.QueryEscape(state))

	c.log.Info("Issued Gemini Web auth URL", zap.String("state", state), zap.String("url", authURL))
	return ctx.JSON(fiber.Map{
		"url":   authURL,
		"state": state,
	})
}

func (c *ManagementController) HandleGetAuthStatus(ctx fiber.Ctx) error {
	state := ctx.Query("state")
	if state == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "missing state",
		})
	}

	st, ok := c.svc.GetState(state)
	if !ok {
		return ctx.JSON(fiber.Map{
			"status": statusWaiting,
		})
	}

	if st.Status == statusComplete {
		if count, err := c.svc.CountGeminiWebAuthFiles(); err == nil && count > 0 {
			return ctx.JSON(fiber.Map{
				"status": statusComplete,
			})
		}
		return ctx.JSON(fiber.Map{
			"status": statusWaiting,
		})
	}

	return ctx.JSON(fiber.Map{
		"status": st.Status,
	})
}

func (c *ManagementController) HandleGeminiWebAuthPage(ctx fiber.Ctx) error {
	state := ctx.Query("state")
	if state == "" {
		return ctx.Status(fiber.StatusBadRequest).SendString("Missing state")
	}

	page := strings.Join([]string{
		"<!doctype html>",
		"<html><head><meta charset=\"utf-8\" /><title>Gemini Web Auth</title>",
		"<style>body{font-family:system-ui,Segoe UI,Arial,sans-serif;padding:24px;max-width:760px;margin:0 auto;}label{display:block;margin-top:12px;}textarea{width:100%;height:120px;}input{width:100%;padding:8px;}</style>",
		"</head><body>",
		"<h2>Gemini Web Authentication</h2>",
		"<p>Paste your Gemini cookies and User-Agent. This will create a credential file in <code>~/.cli-proxy-api</code>.</p>",
		"<form method=\"post\" action=\"/v0/management/gemini-web-auth-complete?state=",
		state,
		"\">",
		"<label>Email</label><input name=\"email\" type=\"email\" required />",
		"<label>Cookie (full cookie header)</label><textarea name=\"cookie\" required></textarea>",
		"<label>User-Agent</label><input name=\"userAgent\" type=\"text\" required />",
		"<button type=\"submit\">Save Auth</button>",
		"</form>",
		"</body></html>",
	}, "")

	ctx.Set("Content-Type", "text/html; charset=utf-8")
	return ctx.SendString(page)
}

func (c *ManagementController) HandleGeminiWebAuthComplete(ctx fiber.Ctx) error {
	state := ctx.Query("state")
	if state == "" {
		return ctx.Status(fiber.StatusBadRequest).SendString("Missing state")
	}

	email := strings.TrimSpace(ctx.FormValue("email"))
	cookie := strings.TrimSpace(ctx.FormValue("cookie"))
	userAgent := strings.TrimSpace(ctx.FormValue("userAgent"))

	if email == "" || cookie == "" || userAgent == "" {
		return ctx.Status(fiber.StatusBadRequest).SendString("Missing required fields")
	}

	if _, err := c.svc.SaveGeminiWebAuth(email, cookie, userAgent); err != nil {
		c.log.Error("Failed to save Gemini Web auth", zap.Error(err))
		return ctx.Status(fiber.StatusInternalServerError).SendString("Failed to save auth")
	}

	if err := c.cookies.ApplyUserAgent(userAgent); err != nil {
		c.log.Error("Failed to apply Gemini user agent", zap.Error(err))
		return ctx.Status(fiber.StatusBadRequest).SendString("Invalid user agent")
	}

	if err := c.cookies.ApplyCookieHeader(cookie); err != nil {
		c.log.Error("Failed to parse Gemini cookies", zap.Error(err))
		return ctx.Status(fiber.StatusBadRequest).SendString("Invalid cookie format")
	}

	c.svc.MarkComplete(state)

	ctx.Set("Content-Type", "text/html; charset=utf-8")
	return ctx.SendString("<html><body><h3>Gemini Web auth saved. You can return to the app.</h3></body></html>")
}
