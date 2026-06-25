package mcp

import (
	"testing"
)

// ---------------------------------------------------------------------------
// validateToolName — security-critical: MCP tool call authorization (#7495)
// ---------------------------------------------------------------------------

func TestValidateToolName(t *testing.T) {
	allowedTools := map[string]bool{
		"get_pods":        true,
		"get_deployments": true,
		"disabled_tool":   false,
	}

	tests := []struct {
		name    string
		tool    string
		wantErr bool
		errMsg  string
	}{
		{"allowed tool passes", "get_pods", false, ""},
		{"another allowed tool passes", "get_deployments", false, ""},
		{"empty name rejected", "", true, "tool name is required"},
		{"unknown tool rejected", "dangerous_tool", true, "tool not allowed"},
		{"explicitly disabled tool rejected", "disabled_tool", true, "tool not allowed"},
		{"case sensitive - wrong case rejected", "Get_Pods", true, "tool not allowed"},
		{"space in name rejected", " get_pods", true, "tool not allowed"},
		{"injection attempt rejected", "get_pods; rm -rf /", true, "tool not allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateToolName(tt.tool, allowedTools)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateToolNameEmptyAllowlist(t *testing.T) {
	emptyMap := map[string]bool{}
	err := validateToolName("any_tool", emptyMap)
	if err == nil {
		t.Error("expected error with empty allowlist, got nil")
	}
}

func TestValidateToolNameNilMap(t *testing.T) {
	// nil map should reject all tools (safe default)
	err := validateToolName("any_tool", nil)
	if err == nil {
		t.Error("expected error with nil allowlist, got nil")
	}
}

// ---------------------------------------------------------------------------
// classifyComponent — network stats component classification
// ---------------------------------------------------------------------------

func TestClassifyComponent(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		want   string
	}{
		{"kubevirt virt-launcher", map[string]string{"app": "virt-launcher"}, "kubevirt"},
		{"k3s", map[string]string{"app": "k3s"}, "k3s"},
		{"ovn", map[string]string{"app": "ovnkube-node"}, "ovn"},
		{"unknown app returns empty", map[string]string{"app": "nginx"}, ""},
		{"no app label returns empty", map[string]string{"tier": "frontend"}, ""},
		{"empty labels returns empty", map[string]string{}, ""},
		{"nil labels returns empty", nil, ""},
		{"app label empty string", map[string]string{"app": ""}, ""},
		{"extra labels ignored", map[string]string{"app": "k3s", "env": "prod"}, "k3s"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyComponent(tt.labels)
			if got != tt.want {
				t.Errorf("classifyComponent(%v) = %q, want %q", tt.labels, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseWarningEventsLimit — input validation for SSE stream limits
// ---------------------------------------------------------------------------

func TestParseWarningEventsLimit(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want int
	}{
		{"empty returns default", "", defaultWarningEventsLimit},
		{"valid number", "100", 100},
		{"max value clamped", "9999", maxWarningEventsLimit},
		{"exactly max allowed", "500", maxWarningEventsLimit},
		{"zero returns default", "0", defaultWarningEventsLimit},
		{"negative returns default", "-5", defaultWarningEventsLimit},
		{"non-numeric returns default", "abc", defaultWarningEventsLimit},
		{"float returns default", "3.14", defaultWarningEventsLimit},
		{"one is valid minimum", "1", 1},
		{"just below max", "499", 499},
		{"whitespace returns default", " ", defaultWarningEventsLimit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseWarningEventsLimit(tt.raw)
			if got != tt.want {
				t.Errorf("parseWarningEventsLimit(%q) = %d, want %d", tt.raw, got, tt.want)
			}
		})
	}
}
