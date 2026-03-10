package gemini

import (
	"bufio"
	"context"
	"fmt"
	"sync"
	"time"

	common "gemini-web-to-api/internal/commons/utils"
	"gemini-web-to-api/internal/modules/gemini/dto"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"

	"crypto/rand"
	"encoding/hex"
)

type GeminiController struct {
	service *GeminiService
	log     *zap.Logger
	mu      sync.RWMutex
	store   *taskStore
}

func NewGeminiController(service *GeminiService) *GeminiController {
	return &GeminiController{
		service: service,
		log:     zap.NewNop(), // Will be injected via wire if needed
		store:   newTaskStore(),
	}
}

// SetLogger sets the logger for this handler (for dependency injection)
func (h *GeminiController) SetLogger(log *zap.Logger) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.log = log
}

// IsHealthy returns the health status of the underlying Gemini service
func (h *GeminiController) IsHealthy() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.service == nil {
		return false
	}
	return h.service.IsHealthy()
}

// --- Official Gemini API (v1beta) ---

// HandleV1BetaModels returns the list of models in Gemini format
// @Summary List Gemini Models
// @Description Returns a list of models supported by the Gemini API
// @Tags Gemini
// @Accept json
// @Produce json
// @Success 200 {object} dto.GeminiModelsResponse
// @Router /gemini/v1beta/models [get]
func (h *GeminiController) HandleV1BetaModels(c fiber.Ctx) error {
	h.mu.RLock()
	defer h.mu.RUnlock()

	availableModels := h.service.ListModels()
	var geminiModels []dto.GeminiModel
	for _, m := range availableModels {
		geminiModels = append(geminiModels, dto.GeminiModel{
			Name:                       "models/" + m.ID,
			DisplayName:                m.ID,
			SupportedGenerationMethods: []string{"generateContent", "streamGenerateContent"},
		})
	}
	return c.JSON(dto.GeminiModelsResponse{Models: geminiModels})
}

// HandleV1BetaGenerateContent handles the official Gemini generateContent endpoint
// @Summary Generate Content (Gemini)
// @Description Generates content using the Gemini model
// @Tags Gemini
// @Accept json
// @Produce json
// @Param model path string true "Model ID"
// @Param request body dto.GeminiGenerateRequest true "Generate Request"
// @Success 200 {object} dto.GeminiGenerateResponse
// @Router /gemini/v1beta/models/{model}:generateContent [post]
func (h *GeminiController) HandleV1BetaGenerateContent(c fiber.Ctx) error {
	h.mu.RLock()
	defer h.mu.RUnlock()

	model := c.Params("model")
	var req dto.GeminiGenerateRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(common.ErrorToResponse(fmt.Errorf("invalid request body: %w", err), "invalid_request_error"))
	}

	// Add timeout to context
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	response, err := h.service.GenerateContent(ctx, model, req)
	if err != nil {
		if err.Error() == "empty content" {
			return c.Status(fiber.StatusBadRequest).JSON(common.ErrorToResponse(err, "invalid_request_error"))
		}
		h.log.Error("GenerateContent failed", zap.Error(err), zap.String("model", model))
		return c.Status(fiber.StatusInternalServerError).JSON(common.ErrorToResponse(err, "api_error"))
	}

	return c.JSON(response)
}

// HandleV1BetaStreamGenerateContent handles the official Gemini streaming endpoint
// @Summary Stream Generate Content (Gemini)
// @Description Streams generated content using the Gemini model
// @Tags Gemini
// @Accept json
// @Produce json
// @Param model path string true "Model ID"
// @Param request body dto.GeminiGenerateRequest true "Generate Request"
// @Success 200 {string} string "Chunked response"
// @Router /gemini/v1beta/models/{model}:streamGenerateContent [post]
func (h *GeminiController) HandleV1BetaStreamGenerateContent(c fiber.Ctx) error {
	h.mu.RLock()
	defer h.mu.RUnlock()

	model := c.Params("model")
	var req dto.GeminiGenerateRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(common.ErrorToResponse(fmt.Errorf("invalid request body: %w", err), "invalid_request_error"))
	}

	c.Set("Content-Type", "application/json")
	c.Set("Transfer-Encoding", "chunked")

	c.RequestCtx().SetBodyStreamWriter(func(w *bufio.Writer) {
		// Add timeout to context inside stream writer
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		resp, err := h.service.GenerateContent(ctx, model, req)
		if err != nil {
			h.log.Error("GenerateContent streaming failed", zap.Error(err), zap.String("model", model))
			errResponse := common.ErrorToResponse(err, "api_error")
			_ = common.SendStreamChunk(w, h.log, errResponse)
			return
		}

		// Handle empty response gracefully
		var text string
		if len(resp.Candidates) > 0 && len(resp.Candidates[0].Content.Parts) > 0 {
			text = resp.Candidates[0].Content.Parts[0].Text
		}

		chunks := common.SplitResponseIntoChunks(text, 30)
		for i, content := range chunks {
			chunk := dto.GeminiGenerateResponse{
				Candidates: []dto.Candidate{
					{
						Index: 0,
						Content: dto.Content{
							Role:  "model",
							Parts: []dto.Part{{Text: content}},
						},
					},
				},
			}

			if err := common.SendStreamChunk(w, h.log, chunk); err != nil {
				h.log.Error("Failed to send stream chunk", zap.Error(err), zap.Int("chunk_index", i))
				return
			}

			// Check for context cancellation and sleep
			if !common.SleepWithCancel(ctx, 30*time.Millisecond) {
				h.log.Info("Stream cancelled by client")
				return
			}
		}

		// Send final chunk
		finalChunk := dto.GeminiGenerateResponse{
			Candidates: []dto.Candidate{
				{
					Index:        0,
					FinishReason: "STOP",
				},
			},
		}
		_ = common.SendStreamChunk(w, h.log, finalChunk)
	})

	return nil
}

// HandleDeepResearch handles a synchronous deep research request.
// @Summary Deep Research (synchronous)
// @Description Performs deep research on a topic using Gemini, searching the web and synthesizing a comprehensive report. This is a blocking call that returns only when research is complete (may take several minutes).
// @Tags Gemini
// @Accept json
// @Produce json
// @Param request body dto.DeepResearchRequest true "Deep Research Request"
// @Success 200 {object} dto.DeepResearchResponse
// @Failure 400 {object} object "Bad Request – query is missing"
// @Failure 500 {object} object "Internal Server Error"
// @Router /gemini/v1beta/deepresearch [post]
func (h *GeminiController) HandleDeepResearch(c fiber.Ctx) error {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var req dto.DeepResearchRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(common.ErrorToResponse(fmt.Errorf("invalid request body: %w", err), "invalid_request_error"))
	}
	if req.Query == "" {
		return c.Status(fiber.StatusBadRequest).JSON(common.ErrorToResponse(fmt.Errorf("query field is required"), "invalid_request_error"))
	}

	// Deep research can take several minutes — use a generous timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	h.log.Info("Handling deep research request", zap.String("query", req.Query))

	response, err := h.service.DeepResearch(ctx, req)
	if err != nil {
		h.log.Error("DeepResearch failed", zap.Error(err), zap.String("query", req.Query))
		return c.Status(fiber.StatusInternalServerError).JSON(common.ErrorToResponse(err, "api_error"))
	}

	return c.JSON(response)
}

// HandleDeepResearchStream handles streaming deep research via Server-Sent Events (SSE).
// @Summary Deep Research (streaming SSE)
// @Description Streams deep research progress in real-time using Server-Sent Events (SSE).
// Each SSE event carries a JSON payload with field "event": "progress"|"source"|"step"|"result"|"error"|"done".
// @Tags Gemini
// @Accept json
// @Produce text/event-stream
// @Param request body dto.DeepResearchRequest true "Deep Research Request"
// @Success 200 {string} string "SSE stream of DeepResearchStreamEvent JSON objects"
// @Failure 400 {object} object "Bad Request – query is missing"
// @Router /gemini/v1beta/deepresearch/stream [post]
func (h *GeminiController) HandleDeepResearchStream(c fiber.Ctx) error {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var req dto.DeepResearchRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(common.ErrorToResponse(fmt.Errorf("invalid request body: %w", err), "invalid_request_error"))
	}
	if req.Query == "" {
		return c.Status(fiber.StatusBadRequest).JSON(common.ErrorToResponse(fmt.Errorf("query field is required"), "invalid_request_error"))
	}

	// SSE headers
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Set("X-Accel-Buffering", "no")

	h.log.Info("Handling streaming deep research request", zap.String("query", req.Query))

	c.RequestCtx().SetBodyStreamWriter(func(w *bufio.Writer) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()

		err := h.service.DeepResearchStream(ctx, req, func(ev dto.DeepResearchStreamEvent) bool {
			return common.SendSSEEvent(w, h.log, ev)
		})
		if err != nil {
			h.log.Error("DeepResearchStream failed", zap.Error(err), zap.String("query", req.Query))
			errEv := dto.DeepResearchStreamEvent{
				Event: "error",
				Error: err.Error(),
			}
			_ = common.SendSSEEvent(w, h.log, errEv)
		}
	})

	return nil
}

// HandleInteractionCreate creates a deep research interaction.
// If stream=true in body: returns an SSE stream of InteractionResponse events (realtime).
// If stream=false:        starts a background task and returns its ID immediately (poll via GET /:id).
// @Summary Create Deep Research Interaction
// @Description Start a deep research task. Set stream=true for realtime SSE progress, or omit for background polling.
// @Tags Gemini
// @Accept json
// @Produce json
// @Param request body dto.InteractionCreateRequest true "Interaction Create Request"
// @Success 202 {object} dto.InteractionResponse
// @Router /gemini/v1beta/deepresearch/create [post]
func (h *GeminiController) HandleInteractionCreate(c fiber.Ctx) error {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var req dto.InteractionCreateRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(common.ErrorToResponse(fmt.Errorf("invalid request body: %w", err), "invalid_request_error"))
	}
	if req.Input == "" {
		return c.Status(fiber.StatusBadRequest).JSON(common.ErrorToResponse(fmt.Errorf("input field is required"), "invalid_request_error"))
	}

	drReq := dto.DeepResearchRequest{
		Query:      req.Input,
		Language:   req.Language,
		MaxSources: req.MaxSources,
	}

	// ── Streaming mode ──────────────────────────────────────────────────────
	if req.Stream {
		c.Set("Content-Type", "text/event-stream")
		c.Set("Cache-Control", "no-cache")
		c.Set("Connection", "keep-alive")
		c.Set("X-Accel-Buffering", "no")

		h.log.Info("Starting streaming interaction", zap.String("query", req.Input))

		c.RequestCtx().SetBodyStreamWriter(func(w *bufio.Writer) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()

			// Track accumulated outputs so each event builds on the last
			var partialText string

			err := h.service.DeepResearchStream(ctx, drReq, func(ev dto.DeepResearchStreamEvent) bool {
				var resp dto.InteractionResponse

				switch ev.Event {
				case "step", "progress":
					// Emit in_progress with any accumulated text so far
					resp = dto.InteractionResponse{
						Status: "in_progress",
						Query:  req.Input,
					}
					if partialText != "" {
						resp.Outputs = []dto.InteractionOutput{{Text: partialText}}
					}

				case "result":
					if ev.Result != nil {
						partialText = ev.Result.Summary
						resp = dto.InteractionResponse{
							ID:          ev.Result.ID,
							Status:      "completed",
							Query:       req.Input,
							Outputs:     []dto.InteractionOutput{{Text: ev.Result.Summary}},
							Sources:     ev.Result.Sources,
							Steps:       ev.Result.Steps,
							DurationMs:  ev.Result.DurationMs,
							CreatedAt:   ev.Result.CreatedAt,
							CompletedAt: ev.Result.CompletedAt,
						}
					}

				case "error":
					resp = dto.InteractionResponse{
						Status: "failed",
						Query:  req.Input,
						Error:  ev.Error,
					}

				case "done":
					// final sentinel – emit completed marker then stop
					resp = dto.InteractionResponse{Status: "completed", Query: req.Input}
					_ = common.SendSSEEvent(w, h.log, resp)
					return false

				default:
					return true // skip source events for this format
				}

				return common.SendSSEEvent(w, h.log, resp)
			})

			if err != nil {
				h.log.Error("Streaming interaction failed", zap.Error(err))
				errResp := dto.InteractionResponse{Status: "failed", Query: req.Input, Error: err.Error()}
				_ = common.SendSSEEvent(w, h.log, errResp)
			}
		})

		return nil
	}

	// ── Background (polling) mode ────────────────────────────────────────────
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	taskID := "task-" + hex.EncodeToString(b)

	task := &researchTask{
		ID:        taskID,
		Status:    taskStatusInProgress,
		Query:     req.Input,
		CreatedAt: time.Now().Unix(),
	}
	h.store.set(task)
	go h.backgroundResearch(taskID, drReq)

	h.log.Info("Created background research task", zap.String("id", taskID), zap.String("query", req.Input))
	return c.Status(fiber.StatusAccepted).JSON(taskToDTO(task))
}


// HandleInteractionGet polls the status of a background research task.
// @Summary Get Deep Research Interaction status
// @Description Returns the current status and result of a background research task.
// @Tags Gemini
// @Produce json
// @Param id path string true "Task ID returned by create"
// @Success 200 {object} dto.InteractionResponse
// @Failure 404 {object} object
// @Router /gemini/v1beta/deepresearch/{id} [get]
func (h *GeminiController) HandleInteractionGet(c fiber.Ctx) error {
	id := c.Params("id")
	task, ok := h.store.get(id)
	if !ok {
		return c.Status(fiber.StatusNotFound).JSON(common.ErrorToResponse(fmt.Errorf("task %q not found", id), "not_found"))
	}
	return c.JSON(taskToDTO(task))
}

// Register registers the Gemini routes on the provided router
func (g *GeminiController) Register(group fiber.Router) {
	group.Get("/models", g.HandleV1BetaModels)
	group.Post("/models/:model\\:generateContent", g.HandleV1BetaGenerateContent)
	group.Post("/models/:model\\:streamGenerateContent", g.HandleV1BetaStreamGenerateContent)

	// Deep Research – synchronous & streaming (custom)
	group.Post("/deepresearch", g.HandleDeepResearch)
	group.Post("/deepresearch/stream", g.HandleDeepResearchStream)

	// Deep Research – async create + poll (custom paths)
	group.Post("/deepresearch/create", g.HandleInteractionCreate)
	group.Get("/deepresearch/:id", g.HandleInteractionGet)

	// Official Gemini Interactions API surface (mirrors generativelanguage.googleapis.com/v1beta/interactions)
	// Backed by Gemini Web cookies – no real API key required.
	group.Post("/interactions", g.HandleInteractionCreate)
	group.Get("/interactions/:id", g.HandleInteractionGet)
}
