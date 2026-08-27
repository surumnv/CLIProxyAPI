package helps

import (
	"encoding/json"
	"testing"

	"github.com/tidwall/gjson"
)

func TestNormalizeClaudeToolSchemasLiftsRootOneOf(t *testing.T) {
	body := []byte(`{"tools":[{"name":"automation_update","input_schema":{
		"type":"object",
		"properties":{},
		"oneOf":[
			{"$ref":"#/$defs/view"},
			{"$ref":"#/$defs/edit"}
		],
		"$defs":{
			"view":{"type":"object","properties":{"id":{"type":"string"},"mode":{"type":"string","enum":["view"]}},"required":["mode","id"],"additionalProperties":false},
			"edit":{"type":"object","properties":{"id":{"type":"string"},"mode":{"type":"string","enum":["edit"]},"patch":{"type":"string"}},"required":["mode","id"],"additionalProperties":false}
		}
	}}]}`)

	updated, rewritten := NormalizeClaudeToolSchemas(body)
	if len(rewritten) != 1 || rewritten[0] != "automation_update" {
		t.Fatalf("expected automation_update to be rewritten, got %v", rewritten)
	}

	schema := gjson.GetBytes(updated, "tools.0.input_schema")
	if schema.Get("oneOf").Exists() {
		t.Fatal("root oneOf should have been removed")
	}
	if got := schema.Get("type").String(); got != "object" {
		t.Fatalf("root type = %q, want object", got)
	}
	for _, name := range []string{"id", "mode", "patch"} {
		if !schema.Get("properties." + name).Exists() {
			t.Fatalf("property %q missing after lift", name)
		}
	}
	// "mode" differs per branch (enum view vs edit), so it becomes a nested anyOf.
	if !schema.Get("properties.mode.anyOf").Exists() {
		t.Fatal("colliding property mode should merge into a nested anyOf")
	}
	// "id" is identical in both branches, so it stays a plain schema.
	if schema.Get("properties.id.anyOf").Exists() {
		t.Fatal("identical property id should not be wrapped in anyOf")
	}
	// required keeps only names every branch required.
	var required []string
	if err := json.Unmarshal([]byte(schema.Get("required").Raw), &required); err != nil {
		t.Fatalf("required is not a string array: %v", err)
	}
	if len(required) != 2 || required[0] != "id" || required[1] != "mode" {
		t.Fatalf("required = %v, want [id mode]", required)
	}
	// $defs must survive: nested properties still reference it.
	if !schema.Get(`$defs.view`).Exists() {
		t.Fatal("$defs should be preserved")
	}
}

func TestNormalizeClaudeToolSchemasDropsClosedContract(t *testing.T) {
	body := []byte(`{"tools":[{"name":"t","input_schema":{
		"type":"object","additionalProperties":false,
		"anyOf":[{"type":"object","properties":{"a":{"type":"string"}}},{"type":"object","properties":{"b":{"type":"string"}}}]
	}}]}`)

	updated, rewritten := NormalizeClaudeToolSchemas(body)
	if len(rewritten) != 1 {
		t.Fatalf("expected one rewrite, got %v", rewritten)
	}
	schema := gjson.GetBytes(updated, "tools.0.input_schema")
	if schema.Get("additionalProperties").Exists() {
		t.Fatal("additionalProperties:false must be dropped on a merged union")
	}
	if schema.Get("required").Exists() {
		t.Fatal("no branch declared required, so required must be absent")
	}
}

func TestNormalizeClaudeToolSchemasLeavesNestedUnionsAlone(t *testing.T) {
	body := []byte(`{"tools":[{"name":"nested","input_schema":{
		"type":"object",
		"properties":{"target":{"anyOf":[{"type":"string"},{"type":"number"}]}},
		"required":["target"]
	}}]}`)

	updated, rewritten := NormalizeClaudeToolSchemas(body)
	if len(rewritten) != 0 {
		t.Fatalf("nested unions must not be rewritten, got %v", rewritten)
	}
	if string(updated) != string(body) {
		t.Fatal("body should be returned unchanged")
	}
}

func TestNormalizeClaudeToolSchemasNoTools(t *testing.T) {
	for _, body := range []string{
		`{"model":"claude-opus-5"}`,
		`{"tools":[]}`,
		`{"tools":"not-an-array"}`,
		`{"tools":[{"name":"t"}]}`,
		`{"tools":[{"name":"t","input_schema":{"type":"object","properties":{"a":{"type":"string"}}}}]}`,
	} {
		updated, rewritten := NormalizeClaudeToolSchemas([]byte(body))
		if len(rewritten) != 0 {
			t.Fatalf("body %s: unexpected rewrite %v", body, rewritten)
		}
		if string(updated) != body {
			t.Fatalf("body %s: should be unchanged, got %s", body, updated)
		}
	}
}

func TestNormalizeClaudeToolSchemasUnresolvableRefIsSkipped(t *testing.T) {
	// A branch pointing at a missing def must not panic and must not invent
	// properties; the union is still lifted so the root stays a plain object.
	body := []byte(`{"tools":[{"name":"t","input_schema":{
		"type":"object","properties":{"keep":{"type":"string"}},
		"oneOf":[{"$ref":"#/$defs/missing"},{"$ref":"https://example.com/x"}],
		"$defs":{"other":{"type":"object"}}
	}}]}`)

	updated, rewritten := NormalizeClaudeToolSchemas(body)
	if len(rewritten) != 1 {
		t.Fatalf("expected the root union to be lifted, got %v", rewritten)
	}
	schema := gjson.GetBytes(updated, "tools.0.input_schema")
	if schema.Get("oneOf").Exists() {
		t.Fatal("root oneOf should have been removed")
	}
	if !schema.Get("properties.keep").Exists() {
		t.Fatal("pre-existing properties must be preserved")
	}
}

func TestNormalizeClaudeToolSchemasCyclicRefIsSkipped(t *testing.T) {
	body := []byte(`{"tools":[{"name":"t","input_schema":{
		"type":"object","properties":{},
		"oneOf":[{"$ref":"#/$defs/a"}],
		"$defs":{"a":{"$ref":"#/$defs/b"},"b":{"$ref":"#/$defs/a"}}
	}}]}`)

	updated, rewritten := NormalizeClaudeToolSchemas(body)
	if len(rewritten) != 1 {
		t.Fatalf("expected the root union to be lifted, got %v", rewritten)
	}
	if gjson.GetBytes(updated, "tools.0.input_schema.oneOf").Exists() {
		t.Fatal("root oneOf should have been removed even with a cyclic $ref")
	}
}

func TestNormalizeClaudeToolSchemasOnlyTouchesOffendingTool(t *testing.T) {
	body := []byte(`{"tools":[
		{"name":"clean","input_schema":{"type":"object","properties":{"a":{"type":"string"}}}},
		{"name":"dirty","input_schema":{"type":"object","properties":{},"oneOf":[{"type":"object","properties":{"b":{"type":"string"}}}]}},
		{"name":"clean2","input_schema":{"type":"object","properties":{"c":{"type":"string"}}}}
	]}`)

	updated, rewritten := NormalizeClaudeToolSchemas(body)
	if len(rewritten) != 1 || rewritten[0] != "dirty" {
		t.Fatalf("rewritten = %v, want [dirty]", rewritten)
	}
	if gjson.GetBytes(updated, "tools.0.input_schema").Raw != gjson.GetBytes(body, "tools.0.input_schema").Raw {
		t.Fatal("clean tool must be untouched")
	}
	if gjson.GetBytes(updated, "tools.2.input_schema").Raw != gjson.GetBytes(body, "tools.2.input_schema").Raw {
		t.Fatal("clean2 tool must be untouched")
	}
	if !gjson.GetBytes(updated, "tools.1.input_schema.properties.b").Exists() {
		t.Fatal("dirty tool branch property should be lifted")
	}
}

func TestNormalizeClaudeToolSchemasEmptyUnionIgnored(t *testing.T) {
	body := []byte(`{"tools":[{"name":"t","input_schema":{"type":"object","properties":{"a":{"type":"string"}},"oneOf":[]}}]}`)
	updated, rewritten := NormalizeClaudeToolSchemas([]byte(body))
	if len(rewritten) != 0 {
		t.Fatalf("an empty union is not a violation, got %v", rewritten)
	}
	if string(updated) != string(body) {
		t.Fatal("body should be unchanged")
	}
}
