package providers

import "context"

// Provider defines the interface that all AI providers must implement
type Provider interface {
	// Init initializes the provider with authentication
	Init(ctx context.Context) error

	// GenerateContent generates a single response
	GenerateContent(ctx context.Context, prompt string, options ...GenerateOption) (*Response, error)

	// GenerateImages generates images from a prompt
	GenerateImages(ctx context.Context, prompt string, options ...GenerateOption) (*Response, error)

	// StartChat creates a new chat session
	StartChat(options ...ChatOption) ChatSession

	// Close cleans up resources
	Close() error

	// GetName returns the provider name
	GetName() string

	// IsHealthy checks if the provider is ready to serve requests
	IsHealthy() bool

	// ListModels returns models supported by this provider
	ListModels() []ModelInfo
}

// ChatSession represents a multi-turn conversation
type ChatSession interface {
	// SendMessage sends a message and returns the response
	SendMessage(ctx context.Context, message string, options ...GenerateOption) (*Response, error)

	// GetMetadata returns session metadata for persistence
	GetMetadata() *SessionMetadata

	// GetHistory returns the conversation history
	GetHistory() []Message

	// Clear clears the conversation history
	Clear()
}

// Response represents a provider's response
type Response struct {
	Text           string         `json:"text"`
	Images         []Image        `json:"images,omitempty"`
	Candidates     []Candidate    `json:"candidates,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	ChosenIndex    int            `json:"chosen_index"`
	ConversationID string         `json:"conversation_id,omitempty"`
	ResponseID     string         `json:"response_id,omitempty"`
}

// Message represents a single message in conversation
type Message struct {
	Role    string  `json:"role"` // "user" or "model"
	Content string  `json:"content"`
	Images  []Image `json:"images,omitempty"`
}

// Image represents an image in the response
type Image struct {
	URL      string `json:"url,omitempty"`
	B64JSON  string `json:"b64_json,omitempty"`
	MimeType string `json:"mime_type,omitempty"`
	Title    string `json:"title,omitempty"`
	AltText  string `json:"alt_text,omitempty"`
	Width    int    `json:"width,omitempty"`
	Height   int    `json:"height,omitempty"`
}

// Candidate represents an alternative response
type Candidate struct {
	ID      string `json:"id"`
	Content string `json:"content"`
}

// SessionMetadata contains information to restore a session
type SessionMetadata struct {
	ConversationID string         `json:"conversation_id"`
	ResponseID     string         `json:"response_id"`
	ChoiceID       string         `json:"choice_id"`
	Model          string         `json:"model,omitempty"`
	Extra          map[string]any `json:"extra,omitempty"`
}

// GenerateOption configures generation behavior
type GenerateOption func(*GenerateConfig)

// GenerateConfig holds generation configuration
type GenerateConfig struct {
	Model          string
	Files          []string
	Temperature    float64
	MaxTokens      int
	ImageCount     int
	ImageSize      string
	ResponseFormat string
}

// ChatOption configures chat session behavior
type ChatOption func(*ChatConfig)

// ChatConfig holds chat session configuration
type ChatConfig struct {
	Model    string
	Metadata *SessionMetadata
}

// WithModel sets the model to use
func WithModel(model string) GenerateOption {
	return func(c *GenerateConfig) {
		c.Model = model
	}
}

// WithFiles adds files to the request
func WithFiles(files []string) GenerateOption {
	return func(c *GenerateConfig) {
		c.Files = files
	}
}

// WithImageCount sets the number of images to generate
func WithImageCount(count int) GenerateOption {
	return func(c *GenerateConfig) {
		c.ImageCount = count
	}
}

// WithImageSize sets the requested image size
func WithImageSize(size string) GenerateOption {
	return func(c *GenerateConfig) {
		c.ImageSize = size
	}
}

// WithResponseFormat sets the preferred response format
func WithResponseFormat(format string) GenerateOption {
	return func(c *GenerateConfig) {
		c.ResponseFormat = format
	}
}

// WithChatModel sets the model for chat session
func WithChatModel(model string) ChatOption {
	return func(c *ChatConfig) {
		c.Model = model
	}
}

// WithChatMetadata restores a previous chat session
func WithChatMetadata(metadata *SessionMetadata) ChatOption {
	return func(c *ChatConfig) {
		c.Metadata = metadata
	}
}
