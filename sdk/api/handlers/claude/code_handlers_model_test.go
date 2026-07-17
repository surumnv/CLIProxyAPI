package claude

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers"
	"github.com/tidwall/gjson"
)

func TestSortClaudeModelsByDisplayName(t *testing.T) {
	models := []map[string]any{
		{"id": "claude-fable-5-dd-b", "display_name": "Zebra"},
		{"id": "claude-a", "display_name": "Alpha"},
		{"id": "claude-c", "display_name": "Alpha"},
		{"id": "claude-fable-5-dd-d", "display_name": "Beta"},
	}
	sortClaudeModelsByDisplayName(models)

	wantIDs := []string{"claude-a", "claude-c", "claude-fable-5-dd-d", "claude-fable-5-dd-b"}
	for i, want := range wantIDs {
		got, _ := models[i]["id"].(string)
		if got != want {
			t.Fatalf("models[%d].id = %q, want %q", i, got, want)
		}
	}
}

func TestClaudeModelsResponseUsesConfiguredDisplayName(t *testing.T) {
	const clientID = "claude-display-name-catalog-test"
	const modelID = "claude-display-name-catalog-test"
	registryRef := registry.GetGlobalRegistry()
	registryRef.RegisterClient(clientID, "claude", []*registry.ModelInfo{{
		ID: modelID, Object: "model", OwnedBy: "test", DisplayName: "Configured Claude Name",
	}})
	t.Cleanup(func() {
		registryRef.UnregisterClient(clientID)
	})

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	NewClaudeCodeAPIHandler(&handlers.BaseAPIHandler{}).ClaudeModels(ctx)

	var response struct {
		Data []struct {
			ID          string `json:"id"`
			DisplayName string `json:"display_name"`
		} `json:"data"`
	}
	if errUnmarshal := json.Unmarshal(recorder.Body.Bytes(), &response); errUnmarshal != nil {
		t.Fatalf("decode response: %v", errUnmarshal)
	}
	for _, model := range response.Data {
		if model.ID == modelID {
			if model.DisplayName != "Configured Claude Name" {
				t.Fatalf("display_name = %q, want Configured Claude Name", model.DisplayName)
			}
			return
		}
	}
	t.Fatalf("model %q not found in response", modelID)
}

func TestClaudeMessagesHandlesClaudeDesktopStartupProbe(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{"model":"claude-opus-4-7","max_tokens":1,"messages":[{"role":"user","content":"."}]}`))
	req.Header.Set("Anthropic-Version", "2023-06-01")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Claude/1.22209.0 Chrome/148.0.7778.271 Electron/42.5.1 Safari/537.36 MSIX")
	ctx.Request = req

	NewClaudeCodeAPIHandler(&handlers.BaseAPIHandler{}).ClaudeMessages(ctx)

	body := recorder.Body.Bytes()
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, body)
	}
	if got := gjson.GetBytes(body, "type").String(); got != "message" {
		t.Fatalf("type = %q, want message; body=%s", got, body)
	}
	if got := gjson.GetBytes(body, "model").String(); got != "claude-opus-4-7" {
		t.Fatalf("model = %q, want claude-opus-4-7; body=%s", got, body)
	}
	if got := gjson.GetBytes(body, "role").String(); got != "assistant" {
		t.Fatalf("role = %q, want assistant; body=%s", got, body)
	}
	if got := gjson.GetBytes(body, "content.0.type").String(); got != "text" {
		t.Fatalf("content.0.type = %q, want text; body=%s", got, body)
	}
	if got := gjson.GetBytes(body, "content.0.text").String(); got != "." {
		t.Fatalf("content.0.text = %q, want .; body=%s", got, body)
	}
	if got := gjson.GetBytes(body, "stop_reason").String(); got != "max_tokens" {
		t.Fatalf("stop_reason = %q, want max_tokens; body=%s", got, body)
	}
	if !gjson.GetBytes(body, "stop_details").Exists() || gjson.GetBytes(body, "stop_details").Type != gjson.Null {
		t.Fatalf("stop_details should be explicit null; body=%s", body)
	}
	if got := gjson.GetBytes(body, "usage.input_tokens").Int(); got != 1 {
		t.Fatalf("usage.input_tokens = %d, want 1; body=%s", got, body)
	}
	if got := gjson.GetBytes(body, "usage.output_tokens").Int(); got != 1 {
		t.Fatalf("usage.output_tokens = %d, want 1; body=%s", got, body)
	}
}

func TestIsClaudeDesktopStartupProbeRejectsClaudeCLI(t *testing.T) {
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	req.Header.Set("Anthropic-Version", "2023-06-01")
	req.Header.Set("User-Agent", "claude-cli/1.0.0")
	ctx.Request = req
	rawJSON := []byte(`{"model":"claude-opus-4-7","max_tokens":1,"messages":[{"role":"user","content":"."}]}`)

	if isClaudeDesktopStartupProbe(ctx, rawJSON) {
		t.Fatal("claude-cli request should not match desktop startup probe")
	}
}

func TestIsClaudeDesktopStartupProbeRejectsConversationShape(t *testing.T) {
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	req.Header.Set("Anthropic-Version", "2023-06-01")
	req.Header.Set("User-Agent", "Mozilla/5.0 Claude/1.22209.0 Electron/42.5.1")
	ctx.Request = req
	rawJSON := []byte(`{"model":"claude-opus-4-7","max_tokens":128,"messages":[{"role":"user","content":"hello"}]}`)

	if isClaudeDesktopStartupProbe(ctx, rawJSON) {
		t.Fatal("normal conversation-shaped request should not match desktop startup probe")
	}
}

func TestRewriteClaudeDDModelInBody(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantModel string
	}{
		{
			name:      "encoded model is decoded",
			body:      `{"model":"claude-fable-5-dd-o4-tpg","messages":[]}`,
			wantModel: "gpt-4o",
		},
		{
			name:      "plain claude model unchanged",
			body:      `{"model":"claude-sonnet-4-6","messages":[]}`,
			wantModel: "claude-sonnet-4-6",
		},
		{
			name:      "encoded model with thinking suffix",
			body:      `{"model":"claude-fable-5-dd-o4-tpg(high)","stream":true}`,
			wantModel: "gpt-4o(high)",
		},
		{
			name:      "missing model field unchanged",
			body:      `{"messages":[]}`,
			wantModel: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rewriteClaudeDDModelInBody([]byte(tt.body))
			if model := gjson.GetBytes(got, "model").String(); model != tt.wantModel {
				t.Fatalf("model = %q, want %q; body=%s", model, tt.wantModel, string(got))
			}
		})
	}
}
