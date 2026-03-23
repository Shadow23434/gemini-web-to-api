package openai

import (
	"github.com/gofiber/fiber/v3"
	"go.uber.org/fx"
)

var Module = fx.Options(
	fx.Provide(NewOpenAIService),
	fx.Provide(NewOpenAIController),
	fx.Invoke(RegisterRoutes),
	fx.Invoke(RegisterRootAliases),
)

func RegisterRoutes(app *fiber.App, c *OpenAIController) {
	// OpenAI routes (prefixed with /openai)
	openaiGroup := app.Group("/openai")
	openaiV1 := openaiGroup.Group("/v1")
	c.Register(openaiV1)
}

// RegisterRootAliases registers OpenAI-compatible endpoints at multiple root paths
// to support clients that auto-detect endpoints with various URL patterns.
func RegisterRootAliases(app *fiber.App, c *OpenAIController) {
	// /v1/* — for clients that append /v1/... to a bare host base URL
	rootV1 := app.Group("/v1")
	c.Register(rootV1)

	// /* — for clients (like Roo Code OpenAI SDK) that use base_url=http://host:port/
	// and append /chat/completions directly without a version prefix
	app.Get("/models", c.HandleModels)
	app.Post("/chat/completions", c.HandleChatCompletions)
	app.Post("/images/generations", c.HandleImageGenerations)
}
