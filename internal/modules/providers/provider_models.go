package providers

import "strings"

// ModelInfo contains basic information about an AI model
type ModelInfo struct {
	ID                      string `json:"id"`
	Created                 int64  `json:"created"`
	OwnedBy                 string `json:"owned_by"`
	Provider                string `json:"provider"` // "gemini", "claude", etc.
	SupportsTextGeneration  bool   `json:"supports_text_generation,omitempty"`
	SupportsImageGeneration bool   `json:"supports_image_generation,omitempty"`
}

func inferModelInfo(id string, created int64) ModelInfo {
	lower := strings.ToLower(strings.TrimSpace(id))
	supportsImageGeneration := supportsImageGenerationModel(lower)
	supportsTextGeneration := !strings.HasPrefix(lower, "imagen-")

	return ModelInfo{
		ID:                      id,
		Created:                 created,
		OwnedBy:                 "google",
		Provider:                "gemini",
		SupportsTextGeneration:  supportsTextGeneration,
		SupportsImageGeneration: supportsImageGeneration,
	}
}

func supportsImageGenerationModel(modelID string) bool {
	lower := strings.ToLower(strings.TrimSpace(modelID))
	return strings.Contains(lower, "image") || strings.Contains(lower, "imagen")
}
