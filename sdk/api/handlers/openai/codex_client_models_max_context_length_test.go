package openai

import "testing"

// TestCodexClientModelsResponseAppliesMaxContextLengthOverride verifies that the
// per-model max-context-length override reaches the Codex client model catalog for
// both template-backed models and models built from the default template.
func TestCodexClientModelsResponseAppliesMaxContextLengthOverride(t *testing.T) {
	const wantOverride = 1048576

	templates, defaultTemplate, err := loadCodexClientModelTemplates()
	if err != nil || defaultTemplate == nil {
		t.Fatalf("loadCodexClientModelTemplates() error = %v, defaultTemplate = %v", err, defaultTemplate)
	}
	if _, ok := templates["gpt-5.5"]; !ok {
		t.Fatal("template for gpt-5.5 missing")
	}
	wantDefault := intModelValue(defaultTemplate, "context_window")
	if wantDefault <= 0 {
		t.Fatalf("default template context_window = %d, want > 0", wantDefault)
	}

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
		bySlug[stringModelValue(model, "slug")] = model
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
		if got := intModelValue(entry, "context_window"); got != testCase.want {
			t.Errorf("%s context_window = %d, want %d", testCase.slug, got, testCase.want)
		}
		if got := intModelValue(entry, "max_context_window"); got != testCase.want {
			t.Errorf("%s max_context_window = %d, want %d", testCase.slug, got, testCase.want)
		}
	}
}
