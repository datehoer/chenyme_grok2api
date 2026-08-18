package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/chenyme/grok2api/backend/internal/domain/account"
	infraegress "github.com/chenyme/grok2api/backend/internal/infra/egress"
	"github.com/chenyme/grok2api/backend/internal/infra/provider/conversation"
	"github.com/chenyme/grok2api/backend/internal/infra/security"
)

func mustToolConfig(t *testing.T, toolsJSON, choiceJSON string) toolConfiguration {
	t.Helper()
	cfg, err := parseToolConfiguration(json.RawMessage(toolsJSON), json.RawMessage(choiceJSON))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func newStreamToolAdapter(t *testing.T) *Adapter {
	t.Helper()
	cipher, err := security.NewCipher(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return NewAdapter(Config{BaseURL: "http://127.0.0.1:1"}, infraegress.NewManager(egressRepositoryStub{}, cipher), cipher, nil, nil)
}

// streamToolSource 把每个 token 编码为 Grok Web 上游的一个 response token 帧。
func streamToolSource(tokens ...string) io.ReadCloser {
	var builder strings.Builder
	for _, token := range tokens {
		builder.WriteString(`{"result":{"response":{"token":`)
		data, _ := json.Marshal(token)
		builder.Write(data)
		builder.WriteString(`,"isThinking":false,"messageTag":"final"}}}`)
	}
	return io.NopCloser(strings.NewReader(builder.String()))
}

func TestValidateRequiredToolCall(t *testing.T) {
	required := toolConfiguration{Choice: "required"}
	required.Functions = []functionTool{{Name: "a"}}
	forced := toolConfiguration{Choice: "required", ForcedName: "a"}
	forced.Functions = []functionTool{{Name: "a"}}
	auto := toolConfiguration{Choice: "auto"}

	if err := validateRequiredToolCall(required, nil); !errors.Is(err, errToolCallRequired) {
		t.Fatalf("required+empty = %v", err)
	}
	if err := validateRequiredToolCall(required, []parsedToolCall{{Name: "a"}}); err != nil {
		t.Fatalf("required+call = %v", err)
	}
	if err := validateRequiredToolCall(forced, []parsedToolCall{{Name: "b"}}); !errors.Is(err, errToolCallRequired) {
		t.Fatalf("forced+wrong-name = %v", err)
	}
	if err := validateRequiredToolCall(forced, []parsedToolCall{{Name: "a"}}); err != nil {
		t.Fatalf("forced+right-name = %v", err)
	}
	if err := validateRequiredToolCall(auto, nil); err != nil {
		t.Fatalf("auto = %v", err)
	}
}

func TestApplyParsedToolCallsRequiredDiscardsProse(t *testing.T) {
	cfg := mustToolConfig(t, `[{"type":"function","name":"get_today_news","description":"Get news","parameters":{"type":"object","properties":{}}}]`, `"required"`)
	parsed := &parsedChat{}
	parsed.appendText("Here is the answer.\n<tool_calls><tool_call><tool_name>get_today_news</tool_name><parameters>{}</parameters></tool_call></tool_calls>")
	if err := applyParsedToolCalls(parsed, cfg); err != nil {
		t.Fatal(err)
	}
	if parsed.Text.String() != "" {
		t.Fatalf("required prose not discarded: %q", parsed.Text.String())
	}
	if len(parsed.ToolCalls) != 1 || parsed.ToolCalls[0].Name != "get_today_news" {
		t.Fatalf("tool calls = %#v", parsed.ToolCalls)
	}
}

func TestApplyParsedToolCallsAutoKeepsProse(t *testing.T) {
	cfg := mustToolConfig(t, `[{"type":"function","name":"get_today_news","description":"Get news","parameters":{"type":"object","properties":{}}}]`, `"auto"`)
	parsed := &parsedChat{}
	parsed.appendText("Sure.\n<tool_calls><tool_call><tool_name>get_today_news</tool_name><parameters>{}</parameters></tool_call></tool_calls>")
	if err := applyParsedToolCalls(parsed, cfg); err != nil {
		t.Fatal(err)
	}
	if parsed.Text.String() != "Sure." {
		t.Fatalf("auto prose = %q", parsed.Text.String())
	}
	if len(parsed.ToolCalls) != 1 {
		t.Fatalf("tool calls = %#v", parsed.ToolCalls)
	}
}

func TestApplyParsedToolCallsRequiredNoCallReturnsError(t *testing.T) {
	cfg := mustToolConfig(t, `[{"type":"function","name":"get_today_news","description":"Get news","parameters":{"type":"object","properties":{}}}]`, `"required"`)
	parsed := &parsedChat{}
	parsed.appendText("Just a plain fabricated answer.")
	if err := applyParsedToolCalls(parsed, cfg); !errors.Is(err, errToolCallRequired) {
		t.Fatalf("err = %v, want errToolCallRequired", err)
	}
}

func TestToolStreamSieveStripsMarkdownFenceAcrossChunks(t *testing.T) {
	sieve := newToolStreamSieve(map[string]struct{}{"get_today_news": {}})
	chunks := []string{
		"```html\n",
		"<tool_calls>",
		"<tool_call><tool_name>get_today_news</tool_name><parameters>{}</parameters></tool_call>",
		"</tool_calls>\n```",
	}
	var leaked strings.Builder
	for _, chunk := range chunks {
		result := sieve.Feed(chunk)
		leaked.WriteString(result.SafeText)
		if result.Complete {
			if len(result.Calls) != 1 || result.Calls[0].Name != "get_today_news" {
				t.Fatalf("calls = %#v", result.Calls)
			}
			if leaked.Len() != 0 {
				t.Fatalf("fence/XML leaked: %q", leaked.String())
			}
			return
		}
	}
	t.Fatal("sieve never completed")
}

func TestWriteStreamToolCallRequiredError(t *testing.T) {
	var buf bytes.Buffer
	writeStreamToolCallRequiredError(&buf, conversation.OperationResponses, "resp_1", errToolCallRequired)
	out := buf.String()
	if !strings.Contains(out, `"response.failed"`) || !strings.Contains(out, `"tool_call_required"`) || strings.Contains(out, `"response.completed"`) {
		t.Fatalf("responses error = %s", out)
	}

	buf.Reset()
	writeStreamToolCallRequiredError(&buf, "chat", "resp_1", errToolCallRequired)
	out = buf.String()
	if !strings.Contains(out, `"error"`) || !strings.Contains(out, `"tool_call_required"`) || !strings.Contains(out, "[DONE]") || strings.Contains(out, `"finish_reason":"stop"`) {
		t.Fatalf("chat error = %s", out)
	}

	buf.Reset()
	writeStreamToolCallRequiredError(&buf, conversation.OperationMessages, "resp_1", errToolCallRequired)
	out = buf.String()
	if !strings.Contains(out, "event: error") || !strings.Contains(out, `"tool_call_required"`) {
		t.Fatalf("messages error = %s", out)
	}
}

func TestStreamResponsesRequiredToolCallFailsClosed(t *testing.T) {
	adapter := newStreamToolAdapter(t)
	tools := mustToolConfig(t, `[{"type":"function","name":"get_today_news","description":"Get news","parameters":{"type":"object","properties":{}}}]`, `"required"`)
	reader := adapter.streamOpenAIResponse(context.Background(), streamToolSource("Here is today's news:", " Nothing happened."), &infraegress.Lease{}, account.Credential{ID: 1}, "resp_1", "grok-chat-fast", conversation.OperationResponses, "prompt", nil, tools, true, conversation.ResponseOptions{})
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if !strings.Contains(text, `"response.failed"`) || !strings.Contains(text, `"tool_call_required"`) {
		t.Fatalf("missing failure: %s", text)
	}
	if strings.Contains(text, `"response.completed"`) || strings.Contains(text, "Here is today's news") || strings.Contains(text, `"output_text.delta"`) {
		t.Fatalf("leaked success/text: %s", text)
	}
}

func TestStreamResponsesRequiredToolCallEmitsFunctionCall(t *testing.T) {
	adapter := newStreamToolAdapter(t)
	tools := mustToolConfig(t, `[{"type":"function","name":"get_today_news","description":"Get news","parameters":{"type":"object","properties":{}}}]`, `"required"`)
	reader := adapter.streamOpenAIResponse(context.Background(), streamToolSource(
		"Sure, here you go:",
		"```html\n<tool_calls>",
		"<tool_call><tool_name>get_today_news</tool_name><parameters>{}</parameters></tool_call>",
		"</tool_calls>\n```",
	), &infraegress.Lease{}, account.Credential{ID: 1}, "resp_2", "grok-chat-fast", conversation.OperationResponses, "prompt", nil, tools, true, conversation.ResponseOptions{})
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if !strings.Contains(text, `"type":"function_call"`) || !strings.Contains(text, `"name":"get_today_news"`) {
		t.Fatalf("missing function_call: %s", text)
	}
	if strings.Contains(text, "Sure, here you go") || strings.Contains(text, "```html") || strings.Contains(text, "<tool_calls") {
		t.Fatalf("leaked prose/fence/XML: %s", text)
	}
	if !strings.Contains(text, `"response.completed"`) {
		t.Fatalf("missing completion: %s", text)
	}
}

func TestStreamChatRequiredToolCallErrors(t *testing.T) {
	adapter := newStreamToolAdapter(t)
	tools := mustToolConfig(t, `[{"type":"function","name":"get_today_news","description":"Get news","parameters":{"type":"object","properties":{}}}]`, `"required"`)
	reader := adapter.streamOpenAIResponse(context.Background(), streamToolSource("Fabricated answer."), &infraegress.Lease{}, account.Credential{ID: 1}, "resp_3", "grok-chat-fast", "chat", "prompt", nil, tools, true, conversation.ResponseOptions{})
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if !strings.Contains(text, `"error"`) || !strings.Contains(text, `"tool_call_required"`) {
		t.Fatalf("missing error: %s", text)
	}
	if strings.Contains(text, `"finish_reason":"stop"`) || strings.Contains(text, "Fabricated answer") {
		t.Fatalf("leaked stop/text: %s", text)
	}
	if !strings.Contains(text, "[DONE]") {
		t.Fatalf("missing [DONE]: %s", text)
	}
}

func TestStreamChatRequiredToolCallFinishesToolCalls(t *testing.T) {
	adapter := newStreamToolAdapter(t)
	tools := mustToolConfig(t, `[{"type":"function","name":"get_today_news","description":"Get news","parameters":{"type":"object","properties":{}}}]`, `"required"`)
	reader := adapter.streamOpenAIResponse(context.Background(), streamToolSource("<tool_calls><tool_call><tool_name>get_today_news</tool_name><parameters>{}</parameters></tool_call></tool_calls>"), &infraegress.Lease{}, account.Credential{ID: 1}, "resp_4", "grok-chat-fast", "chat", "prompt", nil, tools, true, conversation.ResponseOptions{})
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if !strings.Contains(text, `"finish_reason":"tool_calls"`) {
		t.Fatalf("missing tool_calls finish: %s", text)
	}
	if strings.Contains(text, "<tool_calls") {
		t.Fatalf("leaked XML: %s", text)
	}
}
