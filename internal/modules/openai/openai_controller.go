package openai

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"time"

	models "gemini-web-to-api/internal/commons/models"
	utils "gemini-web-to-api/internal/commons/utils"
	"gemini-web-to-api/internal/modules/openai/dto"
	"gemini-web-to-api/internal/modules/providers"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"
)

type OpenAIController struct {
	service *OpenAIService
	log     *zap.Logger
}

func NewOpenAIController(service *OpenAIService) *OpenAIController {
	return &OpenAIController{
		service: service,
		log:     zap.NewNop(),
	}
}

// SetLogger sets the logger for this handler
func (h *OpenAIController) SetLogger(log *zap.Logger) {
	h.log = log
}

// GetModelData returns raw model data for internal use (e.g. unified list)
func (h *OpenAIController) GetModelData() []models.ModelData {
	availableModels := h.service.ListModels()

	var data []models.ModelData
	for _, m := range availableModels {
		data = append(data, models.ModelData{
			ID:      m.ID,
			Object:  "model",
			Created: m.Created,
			OwnedBy: m.OwnedBy,
		})
	}
	return data
}

// HandleModels returns the list of supported models
// @Summary List OpenAI Models
// @Description Returns a list of models supported by the OpenAI-compatible API
// @Tags OpenAI
// @Accept json
// @Produce json
// @Success 200 {object} models.ModelListResponse
// @Router /openai/v1/models [get]
func (h *OpenAIController) HandleModels(c fiber.Ctx) error {
	data := h.GetModelData()

	return c.JSON(models.ModelListResponse{
		Object: "list",
		Data:   data,
	})
}

// HandleChatCompletions accepts requests in OpenAI format
// @Summary Chat Completions (OpenAI)
// @Description Generates a completion for the chat message (supports stream=true)
// @Tags OpenAI
// @Accept json
// @Produce json
// @Param request body dto.ChatCompletionRequest true "Chat Completion Request"
// @Success 200 {object} dto.ChatCompletionResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /openai/v1/chat/completions [post]
func (h *OpenAIController) HandleChatCompletions(c fiber.Ctx) error {
	var req dto.ChatCompletionRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(utils.ErrorToResponse(fmt.Errorf("invalid request body: %w", err), "invalid_request_error"))
	}

	if req.Stream {
		return h.handleChatCompletionsStream(c, req)
	}

	// Add timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	response, err := h.service.CreateChatCompletion(ctx, req)
	if err != nil {
		h.log.Error("GenerateContent failed", zap.Error(err), zap.String("model", req.Model))
		return c.Status(fiber.StatusInternalServerError).JSON(utils.ErrorToResponse(err, "api_error"))
	}

	return c.JSON(response)
}

// handleChatCompletionsStream handles streaming responses using SSE (Server-Sent Events)
// as expected by OpenAI-compatible clients like Roo Code.
func (h *OpenAIController) handleChatCompletionsStream(c fiber.Ctx, req dto.ChatCompletionRequest) error {
	c.Set("Content-Type", "text/event-stream; charset=utf-8")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Set("X-Accel-Buffering", "no")

	c.RequestCtx().SetBodyStreamWriter(func(w *bufio.Writer) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		response, err := h.service.CreateChatCompletion(ctx, req)
		if err != nil {
			h.log.Error("Stream: GenerateContent failed", zap.Error(err), zap.String("model", req.Model))
			errChunk := map[string]interface{}{
				"error": map[string]string{
					"message": err.Error(),
					"type":    "api_error",
				},
			}
			data := utils.MarshalJSONSafely(h.log, errChunk)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", string(data))
			_, _ = fmt.Fprintf(w, "data: [DONE]\n\n")
			_ = w.Flush()
			return
		}

		id := fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano())
		created := time.Now().Unix()
		text := ""
		if len(response.Choices) > 0 {
			text = response.Choices[0].Message.Content
		}

		// First chunk: send role delta
		roleChunk := dto.ChatCompletionChunk{
			ID:      id,
			Object:  "chat.completion.chunk",
			Created: created,
			Model:   req.Model,
			Choices: []dto.ChunkChoice{
				{Index: 0, Delta: models.Delta{Role: "assistant"}},
			},
		}
		data := utils.MarshalJSONSafely(h.log, roleChunk)
		_, _ = fmt.Fprintf(w, "data: %s\n\n", string(data))
		_ = w.Flush()

		// Content chunks: split by word
		words := strings.Fields(text)
		for i, word := range words {
			content := word
			if i < len(words)-1 {
				content += " "
			}
			chunk := dto.ChatCompletionChunk{
				ID:      id,
				Object:  "chat.completion.chunk",
				Created: created,
				Model:   req.Model,
				Choices: []dto.ChunkChoice{
					{Index: 0, Delta: models.Delta{Content: content}},
				},
			}
			chunkData := utils.MarshalJSONSafely(h.log, chunk)
			if _, err := fmt.Fprintf(w, "data: %s\n\n", string(chunkData)); err != nil {
				h.log.Error("Stream: failed to write chunk", zap.Error(err), zap.Int("word_index", i))
				return
			}
			if !utils.SleepWithCancel(ctx, 10*time.Millisecond) {
				return
			}
			if err := w.Flush(); err != nil {
				return
			}
		}

		// Final chunk: finish_reason=stop
		finalChunk := dto.ChatCompletionChunk{
			ID:      id,
			Object:  "chat.completion.chunk",
			Created: created,
			Model:   req.Model,
			Choices: []dto.ChunkChoice{
				{Index: 0, Delta: models.Delta{}, FinishReason: "stop"},
			},
		}
		finalData := utils.MarshalJSONSafely(h.log, finalChunk)
		_, _ = fmt.Fprintf(w, "data: %s\n\n", string(finalData))
		_, _ = fmt.Fprintf(w, "data: [DONE]\n\n")
		_ = w.Flush()
	})

	return nil
}

// HandleImageGenerations accepts requests in OpenAI image generation format.
// @Summary Image Generations (OpenAI)
// @Description Generates images from a prompt using the selected model
// @Tags OpenAI
// @Accept json
// @Produce json
// @Param request body dto.ImageGenerationRequest true "Image Generation Request"
// @Success 200 {object} dto.ImageGenerationResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /openai/v1/images/generations [post]
func (h *OpenAIController) HandleImageGenerations(c fiber.Ctx) error {
	var req dto.ImageGenerationRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(utils.ErrorToResponse(fmt.Errorf("invalid request body: %w", err), "invalid_request_error"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	response, err := h.service.CreateImageGeneration(ctx, req)
	if err != nil {
		status := fiber.StatusInternalServerError
		if err.Error() == "prompt is required" || err.Error() == "n must be non-negative" || strings.Contains(err.Error(), "does not support image generation") {
			status = fiber.StatusBadRequest
		}
		h.log.Error("GenerateImages failed", zap.Error(err), zap.String("model", req.Model))
		return c.Status(status).JSON(utils.ErrorToResponse(err, "api_error"))
	}

	return c.JSON(response)
}

func (h *OpenAIController) convertToOpenAIFormat(response *providers.Response, model string) dto.ChatCompletionResponse {
	return dto.ChatCompletionResponse{
		ID:      fmt.Sprintf("chatcmpl-%d", time.Now().Unix()),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   model,
		Choices: []dto.Choice{{
			Index: 0,
			Message: models.Message{
				Role:    "assistant",
				Content: response.Text,
			},
			FinishReason: "stop",
		}},
		Usage: models.Usage{
			PromptTokens:     0,
			CompletionTokens: 0,
			TotalTokens:      0,
		},
	}
}

// Register registers the OpenAI routes onto the provided group
func (c *OpenAIController) Register(group fiber.Router) {
	group.Get("/models", c.HandleModels)
	group.Post("/chat/completions", c.HandleChatCompletions)
	group.Post("/images/generations", c.HandleImageGenerations)
}
