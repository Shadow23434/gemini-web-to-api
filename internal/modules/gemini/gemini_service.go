package gemini

import (
	"context"
	"fmt"
	"strings"

	"gemini-web-to-api/internal/modules/gemini/dto"
	"gemini-web-to-api/internal/modules/providers"

	"go.uber.org/zap"
)

type GeminiService struct {
	client *providers.Client
	log    *zap.Logger
}

func NewGeminiService(client *providers.Client, log *zap.Logger) *GeminiService {
	return &GeminiService{
		client: client,
		log:    log,
	}
}

func (s *GeminiService) ListModels() []providers.ModelInfo {
	return s.client.ListModels()
}

func (s *GeminiService) GenerateContent(ctx context.Context, modelID string, req dto.GeminiGenerateRequest) (*dto.GeminiGenerateResponse, error) {
	prompt := strings.TrimSpace(extractPrompt(req))
	if prompt == "" {
		return nil, fmt.Errorf("empty content")
	}

	response, err := s.client.GenerateContent(ctx, prompt, providers.WithModel(modelID))
	if err != nil {
		return nil, err
	}

	return buildGeminiGenerateResponse(response), nil
}

func (s *GeminiService) GenerateImages(ctx context.Context, modelID string, req dto.GeminiImageGenerationRequest) (*dto.GeminiGenerateResponse, error) {
	prompt := strings.TrimSpace(req.Prompt)
	if prompt == "" {
		return nil, fmt.Errorf("empty prompt")
	}

	opts := []providers.GenerateOption{providers.WithModel(modelID)}
	if req.ImageCount > 0 {
		opts = append(opts, providers.WithImageCount(req.ImageCount))
	}
	if req.ImageSize != "" {
		opts = append(opts, providers.WithImageSize(req.ImageSize))
	}
	if req.ResponseMimeType != "" {
		opts = append(opts, providers.WithResponseFormat(req.ResponseMimeType))
	}

	response, err := s.client.GenerateImages(ctx, prompt, opts...)
	if err != nil {
		return nil, err
	}

	return buildGeminiGenerateResponse(response), nil
}

func extractPrompt(req dto.GeminiGenerateRequest) string {
	var promptBuilder strings.Builder
	for _, content := range req.Contents {
		for _, part := range content.Parts {
			if part.Text != "" {
				promptBuilder.WriteString(part.Text)
				promptBuilder.WriteString("\n")
			}
		}
	}
	return promptBuilder.String()
}

func buildGeminiGenerateResponse(response *providers.Response) *dto.GeminiGenerateResponse {
	parts := make([]dto.Part, 0, len(response.Images)+1)
	if strings.TrimSpace(response.Text) != "" {
		parts = append(parts, dto.Part{Text: response.Text})
	}
	for _, image := range response.Images {
		part := dto.Part{}
		if image.B64JSON != "" {
			part.InlineData = &dto.InlineData{MimeType: image.MimeType, Data: image.B64JSON}
		} else if image.URL != "" {
			part.FileData = &dto.FileData{MimeType: image.MimeType, FileURI: image.URL}
		}
		if part.InlineData != nil || part.FileData != nil {
			parts = append(parts, part)
		}
	}
	if len(parts) == 0 {
		parts = append(parts, dto.Part{Text: ""})
	}

	return &dto.GeminiGenerateResponse{
		Candidates: []dto.Candidate{{
			Index: 0,
			Content: dto.Content{
				Role:  "model",
				Parts: parts,
			},
			FinishReason: "STOP",
		}},
		UsageMetadata: &dto.UsageMetadata{TotalTokenCount: 0},
	}
}

func (s *GeminiService) IsHealthy() bool {
	return s.client.IsHealthy()
}

func (s *GeminiService) Client() *providers.Client {
	return s.client
}
