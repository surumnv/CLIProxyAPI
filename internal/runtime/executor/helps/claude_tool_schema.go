package helps

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// claudeSchemaUnionKeys are the JSON Schema union combinators that Anthropic
// rejects when they appear at the *top level* of a tool's input_schema.
var claudeSchemaUnionKeys = []string{"oneOf", "anyOf", "allOf"}

// claudeSchemaMaxRefHops bounds local $ref chasing so a malformed schema with a
// reference cycle cannot spin forever.
const claudeSchemaMaxRefHops = 16

// NormalizeClaudeToolSchemas rewrites tool input_schema objects that carry a
// top-level oneOf/anyOf/allOf into a plain object schema.
//
// Anthropic documents input_schema as a JSON Schema *subset*: the root must be a
// concrete object. A root-level union is accepted by first-party Anthropic but
// makes several third-party relays fail the whole request — one returns
// HTTP 502 "Upstream service temporarily unavailable" with no indication of
// which tool caused it. Codex sends such a schema for
// mcp__codex_app__automation_update (a root `oneOf` of four `$ref` branches
// beside an empty `properties`), so every Codex turn carrying that tool failed
// while the same conversation succeeded from Claude Desktop.
//
// Unions nested *inside* a property are legal and are left untouched. Only the
// root is lifted: each branch is resolved (following local `#/$defs/...`
// references), its properties are merged into the root `properties`, and keys
// that collide across branches become a nested anyOf — which upstream accepts.
//
// The rewrite is deliberately lossy in one direction only: it widens what the
// model may emit (branch-specific constraints become optional) rather than
// narrowing it, so a call that was valid before stays valid. `required` is kept
// only for names every branch required, and a root `additionalProperties:false`
// is dropped because a merged union can no longer honor a closed contract.
func NormalizeClaudeToolSchemas(body []byte) ([]byte, []string) {
	tools := gjson.GetBytes(body, "tools")
	if !tools.Exists() || !tools.IsArray() {
		return body, nil
	}

	var normalized []string
	updated := body
	tools.ForEach(func(index, tool gjson.Result) bool {
		schema := tool.Get("input_schema")
		if !schema.Exists() || !schema.IsObject() {
			return true
		}
		if !hasTopLevelUnion(schema) {
			return true
		}

		var root map[string]any
		if err := json.Unmarshal([]byte(schema.Raw), &root); err != nil {
			return true
		}
		rewritten, changed := normalizeSchemaRoot(root)
		if !changed {
			return true
		}
		path := "tools." + index.String() + ".input_schema"
		next, err := sjson.SetBytes(updated, path, rewritten)
		if err != nil {
			return true
		}
		updated = next
		if name := strings.TrimSpace(tool.Get("name").String()); name != "" {
			normalized = append(normalized, name)
		}
		return true
	})
	return updated, normalized
}

// hasTopLevelUnion reports whether the schema root carries a non-empty union key.
func hasTopLevelUnion(schema gjson.Result) bool {
	for _, key := range claudeSchemaUnionKeys {
		if value := schema.Get(key); value.Exists() && value.IsArray() && len(value.Array()) > 0 {
			return true
		}
	}
	return false
}

// normalizeSchemaRoot lifts root-level union branches into the root properties.
func normalizeSchemaRoot(root map[string]any) (map[string]any, bool) {
	defs, _ := root["$defs"].(map[string]any)

	properties, _ := root["properties"].(map[string]any)
	if properties == nil {
		properties = make(map[string]any)
	}

	requiredPerBranch := make([]map[string]bool, 0, len(claudeSchemaUnionKeys))
	changed := false

	for _, key := range claudeSchemaUnionKeys {
		branches, ok := root[key].([]any)
		if !ok || len(branches) == 0 {
			continue
		}
		delete(root, key)
		changed = true

		for _, raw := range branches {
			branch, okBranch := raw.(map[string]any)
			if !okBranch {
				continue
			}
			resolved := resolveLocalRef(branch, defs)
			if resolved == nil {
				resolved = branch
			}
			if branchProps, okProps := resolved["properties"].(map[string]any); okProps {
				for name, sub := range branchProps {
					if existing, exists := properties[name]; exists {
						properties[name] = mergePropertySchemas(existing, sub)
						continue
					}
					properties[name] = sub
				}
			}
			requiredPerBranch = append(requiredPerBranch, stringSet(resolved["required"]))
		}
	}

	if !changed {
		return root, false
	}

	root["type"] = "object"
	root["properties"] = properties

	if required := intersectRequired(requiredPerBranch, properties, root["required"]); len(required) > 0 {
		root["required"] = required
	} else {
		delete(root, "required")
	}

	// A merged union cannot keep a closed object contract: the surviving
	// properties are the union of all branches, so any single valid call would
	// look like it carries unexpected keys.
	if value, ok := root["additionalProperties"].(bool); ok && !value {
		delete(root, "additionalProperties")
	}

	return root, true
}

// resolveLocalRef follows local "#/$defs/..." references. It returns nil when the
// reference is external, cyclic, or unresolvable.
func resolveLocalRef(node map[string]any, defs map[string]any) map[string]any {
	seen := make(map[string]bool)
	current := node
	for hop := 0; hop < claudeSchemaMaxRefHops; hop++ {
		ref, ok := current["$ref"].(string)
		if !ok {
			return current
		}
		if !strings.HasPrefix(ref, "#/") || seen[ref] {
			return nil
		}
		seen[ref] = true

		target := any(defs)
		for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			if part == "$defs" {
				continue
			}
			container, okContainer := target.(map[string]any)
			if !okContainer {
				return nil
			}
			next, exists := container[part]
			if !exists {
				return nil
			}
			target = next
		}
		resolved, okResolved := target.(map[string]any)
		if !okResolved {
			return nil
		}
		current = resolved
	}
	return nil
}

// mergePropertySchemas combines two schemas for the same property name into a
// nested anyOf, flattening anyOf wrappers and dropping duplicates.
func mergePropertySchemas(existing, incoming any) any {
	if schemasEqual(existing, incoming) {
		return existing
	}

	variants := make([]any, 0, 2)
	variants = appendSchemaVariants(variants, existing)
	variants = appendSchemaVariants(variants, incoming)

	deduped := make([]any, 0, len(variants))
	for _, variant := range variants {
		duplicate := false
		for _, kept := range deduped {
			if schemasEqual(kept, variant) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			deduped = append(deduped, variant)
		}
	}
	if len(deduped) == 1 {
		return deduped[0]
	}
	return map[string]any{"anyOf": deduped}
}

// appendSchemaVariants unwraps a bare {"anyOf": [...]} so merging stays flat.
func appendSchemaVariants(variants []any, schema any) []any {
	if object, ok := schema.(map[string]any); ok && len(object) == 1 {
		if nested, okNested := object["anyOf"].([]any); okNested {
			return append(variants, nested...)
		}
	}
	return append(variants, schema)
}

// schemasEqual compares two schema fragments structurally.
func schemasEqual(a, b any) bool {
	left, errLeft := json.Marshal(a)
	right, errRight := json.Marshal(b)
	if errLeft != nil || errRight != nil {
		return false
	}
	return string(left) == string(right)
}

// stringSet converts a JSON array of strings into a set.
func stringSet(value any) map[string]bool {
	out := make(map[string]bool)
	items, ok := value.([]any)
	if !ok {
		return out
	}
	for _, item := range items {
		if name, okName := item.(string); okName {
			out[name] = true
		}
	}
	return out
}

// intersectRequired keeps only the names required by every branch (plus any that
// were already required at the root) and that survive in the merged properties.
func intersectRequired(perBranch []map[string]bool, properties map[string]any, rootRequired any) []string {
	keep := make(map[string]bool)

	if len(perBranch) > 0 {
		for name := range perBranch[0] {
			keep[name] = true
		}
		for _, branch := range perBranch[1:] {
			for name := range keep {
				if !branch[name] {
					delete(keep, name)
				}
			}
		}
	}
	for name := range stringSet(rootRequired) {
		keep[name] = true
	}

	out := make([]string, 0, len(keep))
	for name := range keep {
		if _, exists := properties[name]; exists {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
