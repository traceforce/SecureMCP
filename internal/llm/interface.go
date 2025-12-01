package llm

import "context"

type ChatMessage struct {
	Role    string
	Content string
}

type ChatClient interface {
	Chat(ctx context.Context, systemPrompt string, messages []ChatMessage) (string, error)
}
