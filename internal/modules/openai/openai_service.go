package openai

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gemini-web-to-api/internal/commons/models"
	"gemini-web-to-api/internal/commons/utils"
	"gemini-web-to-api/internal/modules/openai/dto"
	"gemini-web-to-api/internal/modules/providers"

	"go.uber.org/zap"
)

type OpenAIService struct {
	client *providers.Client
	log    *zap.Logger
}

func NewOpenAIService(client *providers.Client, log *zap.Logger) *OpenAIService {
	return &OpenAIService{
		client: client,
		log:    log,
	}
}

func (s *OpenAIService) ListModels() []providers.ModelInfo {
	return s.client.ListModels()
}

func (s *OpenAIService) CreateChatCompletion(ctx context.Context, req dto.ChatCompletionRequest) (*dto.ChatCompletionResponse, error) {
	commonMessages := make([]models.Message, 0, len(req.Messages))
	for _, m := range req.Messages {
		commonMessages = append(commonMessages, m.ToCommonMessage())
	}

	if err := utils.ValidateMessages(commonMessages); err != nil {
		return nil, err
	}
	if err := utils.ValidateGenerationRequest(req.Model, req.MaxTokens, req.Temperature); err != nil {
		return nil, err
	}

	prompt := utils.BuildPromptFromMessages(commonMessages, "")
	if prompt == "" {
		return nil, fmt.Errorf("no valid content in messages")
	}

	opts := []providers.GenerateOption{}
	if req.Model != "" {
		opts = append(opts, providers.WithModel(req.Model))
	}

	response, err := s.client.GenerateContent(ctx, prompt, opts...)
	if err != nil {
		return nil, err
	}

	return &dto.ChatCompletionResponse{
		ID:      fmt.Sprintf("chatcmpl-%d", time.Now().Unix()),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   req.Model,
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
	}, nil
}

func (s *OpenAIService) CreateImageGeneration(ctx context.Context, req dto.ImageGenerationRequest) (*dto.ImageGenerationResponse, error) {
	if strings.TrimSpace(req.Prompt) == "" {
		return nil, fmt.Errorf("prompt is required")
	}
	if req.N < 0 {
		return nil, fmt.Errorf("n must be non-negative")
	}

	opts := []providers.GenerateOption{}
	if req.Model != "" {
		opts = append(opts, providers.WithModel(req.Model))
	}
	if req.N > 0 {
		opts = append(opts, providers.WithImageCount(req.N))
	}
	if req.Size != "" {
		opts = append(opts, providers.WithImageSize(req.Size))
	}
	if req.ResponseFormat != "" {
		opts = append(opts, providers.WithResponseFormat(req.ResponseFormat))
	}

	response, err := s.client.GenerateImages(ctx, req.Prompt, opts...)
	if err != nil {
		return nil, err
	}

	data := make([]dto.ImageData, 0, len(response.Images))
	for _, image := range response.Images {
		data = append(data, dto.ImageData{
			URL:     image.URL,
			B64JSON: image.B64JSON,
		})
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("image generation returned no images")
	}

	return &dto.ImageGenerationResponse{
		Created: time.Now().Unix(),
		Data:    data,
	}, nil
}
