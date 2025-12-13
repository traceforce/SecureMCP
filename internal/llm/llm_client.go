package llm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/joho/godotenv"
)

const (
	LLM_TYPE_UNKNOWN   = 0
	LLM_TYPE_ANTHROPIC = 1
	LLM_TYPE_OPENAI    = 2
	LLM_TYPE_AWS       = 3
)

type LLMClient struct {
	ChatClient ChatClient
	llmType    int
	timeout    time.Duration
}

const (
	MAX_TOKENS_ANTHROPIC = 12000
	MAX_TOKENS_OPENAI    = 12000
	MAX_TOKENS_AWS       = 2048
)

// NewLLMClientFromEnvWithModel creates a new LLM client from environment variables
func NewLLMClientFromEnvWithModel(model string, timeout time.Duration) (*LLMClient, error) {
	if model == "" {
		return nil, errors.New("model is required")
	}

	// Try to load environment variables from .env file.Ignores error if .env doesn't exist as we
	// will try to load from the enviornment variables directly
	_ = godotenv.Load()

	llmType := LLM_TYPE_UNKNOWN
	var chatClient ChatClient
	if strings.HasPrefix(strings.ToLower(model), "claude-") {
		llmType = LLM_TYPE_ANTHROPIC
		apiKey := os.Getenv("ANTHROPIC_API_KEY")
		if apiKey == "" {
			return nil, errors.New("To use Anthropic models, the Environment variable ANTHROPIC_API_KEY is required")
		}
		chatClient = NewAnthropicClient(apiKey, model)
	} else if strings.HasPrefix(strings.ToLower(model), "gpt-") {
		llmType = LLM_TYPE_OPENAI
		apiKey := os.Getenv("OPENAI_API_KEY")
		if apiKey == "" {
			return nil, errors.New("To use OpenAI models, the Environment variable OPENAI_API_KEY is required")
		}
		chatClient = NewOpenAIClient(apiKey, model)
	} else if strings.HasPrefix(strings.ToLower(model), "arn:aws:bedrock:") && strings.Contains(strings.ToLower(model), "llama") {
		llmType = LLM_TYPE_AWS
		cfg, err := config.LoadDefaultConfig(context.Background())
		if err != nil {
			return nil, fmt.Errorf("To use AWS models, the AWS config must be loaded: %w", err)
		}
		chatClient = NewBedrockLlamaClient(cfg, model)
	} else {
		example := "arn:aws:bedrock:us-east-2:522814721969:inference-profile/us.meta.llama3-2-1b-instruct-v1:0"
		return nil, fmt.Errorf("Unsupported LLM model: %v. If you are using an AWS model, it must be an Meta Llama inference profile ARN starting with 'arn:aws:bedrock:' (e.g. %v)", model, example)
	}

	return &LLMClient{
		ChatClient: chatClient,
		llmType:    llmType,
		timeout:    timeout,
	}, nil
}

// GetType returns the LLM type
func (c *LLMClient) GetType() int {
	return c.llmType
}
