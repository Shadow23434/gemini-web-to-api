package dto

import (
	"encoding/json"
	"strings"

	models "gemini-web-to-api/internal/commons/models"
)

// MessageContent accepts either a plain string or an array/object of content parts.
// It normalizes all text parts into a single text string.
type MessageContent struct {
	Text string
}

type contentPart struct {
	Type      string `json:"type"`
	Text      string `json:"text"`
	InputText string `json:"input_text"`
}

func (mc *MessageContent) UnmarshalJSON(data []byte) error {
	var asString string
	if err := json.Unmarshal(data, &asString); err == nil {
		mc.Text = strings.TrimSpace(asString)
		return nil
	}

	var asObject contentPart
	if err := json.Unmarshal(data, &asObject); err == nil {
		text := strings.TrimSpace(firstNonEmpty(asObject.Text, asObject.InputText))
		mc.Text = text
		return nil
	}

	var asArray []contentPart
	if err := json.Unmarshal(data, &asArray); err == nil {
		parts := make([]string, 0, len(asArray))
		for _, p := range asArray {
			text := strings.TrimSpace(firstNonEmpty(p.Text, p.InputText))
			if text != "" {
				parts = append(parts, text)
			}
		}
		mc.Text = strings.TrimSpace(strings.Join(parts, "\n"))
		return nil
	}

	// Keep empty text for unknown content formats instead of failing hard.
	mc.Text = ""
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// ChatMessage is OpenAI-compatible, but supports multimodal content payloads.
type ChatMessage struct {
	Role    string         `json:"role"`
	Content MessageContent `json:"content"`
}

func (m ChatMessage) ToCommonMessage() models.Message {
	return models.Message{
		Role:    m.Role,
		Content: m.Content.Text,
	}
}

// ChatCompletionRequest represents OpenAI chat completion request
type ChatCompletionRequest struct {
	Model       string           `json:"model"`
	Messages    []ChatMessage    `json:"messages"`
	Stream      bool             `json:"stream,omitempty"`
	Temperature float32          `json:"temperature,omitempty"`
	MaxTokens   int              `json:"max_tokens,omitempty"`
}

// ChatCompletionResponse represents OpenAI chat completion response
type ChatCompletionResponse struct {
	ID      string       `json:"id"`
	Object  string       `json:"object"`
	Created int64        `json:"created"`
	Model   string       `json:"model"`
	Choices []Choice     `json:"choices"`
	Usage   models.Usage `json:"usage"`
}

// Choice represents a response choice
type Choice struct {
	Index        int            `json:"index"`
	Message      models.Message `json:"message"`
	FinishReason string         `json:"finish_reason"`
}

// ChatCompletionChunk represents a streaming chunk
type ChatCompletionChunk struct {
	ID      string        `json:"id"`
	Object  string        `json:"object"`
	Created int64         `json:"created"`
	Model   string        `json:"model"`
	Choices []ChunkChoice `json:"choices"`
}

// ChunkChoice represents a choice in a chunk
type ChunkChoice struct {
	Index        int          `json:"index"`
	Delta        models.Delta `json:"delta"`
	FinishReason string       `json:"finish_reason,omitempty"`
}
