package openai

import "testing"

// TestCodexClientModelsResponseAppliesMaxContextLengthOverride verifies that the
// per-model max-context-length override reaches the Codex client model catalog for
// both template-backed models and models built from the default template.
//
// Upstream moved the catalog builder into internal/client/codex/models, so the
// package-local template helpers this test originally called no longer exist
// here. The override is now exercised through the exported
// CodexClientModelsResponse wrapper, which reaches the same builder.
func TestCodexClientModelsResponseAppliesMaxContextLengthOverride(t *testing.T) {
	const wantOverride = 1048576

	resp := CodexClientModelsResponse([]map[string]any{
		{"id": "deepseek-v4-flash", "max_context_length": wantOverride},
		{"id": "deepseek-v4-pro"},
		{"id": "gpt-5.5", "max_context_length": wantOverride},
	})
	models, ok := resp["models"].([]map[string]any)
	if !ok {
		t.Fatalf("models type = %T, want []map[string]any", resp["models"])
	}

	bySlug := make(map[string]map[string]any, len(models))
	for _, model := range models {
		slug, _ := model["slug"].(string)
		bySlug[slug] = model
	}

	// deepseek-v4-pro carries no override, so its emitted context_window is the
	// default-template value. Deriving the expectation from the response keeps the
	// test correct when upstream retunes that template.
	baseline := bySlug["deepseek-v4-pro"]
	if baseline == nil {
		t.Fatal("missing model \"deepseek-v4-pro\"")
	}
	wantDefault := maxContextLengthTestIntValue(baseline, "context_window")
	if wantDefault <= 0 {
		t.Fatalf("deepseek-v4-pro context_window = %d, want > 0", wantDefault)
	}
	if wantDefault == wantOverride {
		t.Fatalf("default context_window = %d equals the override value, so an applied override would be indistinguishable", wantDefault)
	}

	for _, testCase := range []struct {
		slug string
		want int
	}{
		{slug: "deepseek-v4-flash", want: wantOverride},
		{slug: "deepseek-v4-pro", want: wantDefault},
		{slug: "gpt-5.5", want: wantOverride},
	} {
		entry := bySlug[testCase.slug]
		if entry == nil {
			t.Fatalf("missing model %q", testCase.slug)
		}
		if got := maxContextLengthTestIntValue(entry, "context_window"); got != testCase.want {
			t.Errorf("%s context_window = %d, want %d", testCase.slug, got, testCase.want)
		}
		if got := maxContextLengthTestIntValue(entry, "max_context_window"); got != testCase.want {
			t.Errorf("%s max_context_window = %d, want %d", testCase.slug, got, testCase.want)
		}
	}
}

// maxContextLengthTestIntValue reads an integer catalog field. Template values
// decoded from JSON arrive as float64 while builder-written overrides stay int,
// so both shapes must be accepted.
func maxContextLengthTestIntValue(entry map[string]any, key string) int {
	switch typed := entry[key].(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	default:
		return 0
	}
}
