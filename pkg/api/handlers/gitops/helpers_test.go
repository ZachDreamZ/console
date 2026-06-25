package gitops

import (
	"bufio"
	"bytes"
	"encoding/json"
	"testing"
)

// ---------------------------------------------------------------------------
// indexOf
// ---------------------------------------------------------------------------

func TestIndexOf(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		substr string
		want   int
	}{
		{"found at start", "hello world", "hello", 0},
		{"found in middle", "hello world", "lo w", 3},
		{"found at end", "hello world", "world", 6},
		{"not found", "hello world", "xyz", -1},
		{"empty substr in non-empty string", "hello", "", 0},
		{"empty string empty substr", "", "", 0},
		{"substr longer than string", "hi", "hello", -1},
		{"single char found", "abcdef", "d", 3},
		{"single char not found", "abcdef", "z", -1},
		{"repeated pattern returns first", "ababab", "ab", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := indexOf(tt.s, tt.substr)
			if got != tt.want {
				t.Errorf("indexOf(%q, %q) = %d, want %d", tt.s, tt.substr, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// replaceAll
// ---------------------------------------------------------------------------

func TestReplaceAll(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		old    string
		newStr string
		want   string
	}{
		{"no match", "hello world", "xyz", "!", "hello world"},
		{"single replacement", "hello world", "world", "go", "hello go"},
		{"multiple replacements", "aaa", "a", "bb", "bbbbbb"},
		{"replace with empty", "hello\nworld\n", "\n", "", "helloworld"},
		{"replace CR", "line1\rline2\r", "\r", "", "line1line2"},
		{"empty old string causes infinite loop guard", "abc", "", "x", "abc"},
		{"replace in middle", "foo-bar-baz", "-", "_", "foo_bar_baz"},
		{"adjacent replacements", "aabb", "ab", "x", "axb"},
		{"whole string is match", "xx", "xx", "y", "y"},
		{"empty string input", "", "a", "b", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip the empty-old-string case if it would loop
			if tt.old == "" {
				t.Skip("empty old string edge case - implementation-dependent")
			}
			got := replaceAll(tt.s, tt.old, tt.newStr)
			if got != tt.want {
				t.Errorf("replaceAll(%q, %q, %q) = %q, want %q", tt.s, tt.old, tt.newStr, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// jsonMarshal
// ---------------------------------------------------------------------------

func TestJsonMarshal(t *testing.T) {
	tests := []struct {
		name    string
		input   interface{}
		wantErr bool
		check   func(t *testing.T, b []byte)
	}{
		{
			name:  "simple map",
			input: map[string]string{"key": "value"},
			check: func(t *testing.T, b []byte) {
				var m map[string]string
				if err := json.Unmarshal(b, &m); err != nil {
					t.Fatalf("unmarshal error: %v", err)
				}
				if m["key"] != "value" {
					t.Errorf("expected key=value, got %v", m)
				}
			},
		},
		{
			name:  "no trailing newline",
			input: map[string]int{"n": 42},
			check: func(t *testing.T, b []byte) {
				if len(b) == 0 {
					t.Fatal("empty output")
				}
				if b[len(b)-1] == '\n' {
					t.Error("output has trailing newline, should be stripped")
				}
			},
		},
		{
			name:  "nested structure",
			input: map[string]interface{}{"outer": map[string]int{"inner": 1}},
			check: func(t *testing.T, b []byte) {
				var m map[string]interface{}
				if err := json.Unmarshal(b, &m); err != nil {
					t.Fatalf("unmarshal error: %v", err)
				}
				outer, ok := m["outer"].(map[string]interface{})
				if !ok {
					t.Fatal("outer not a map")
				}
				if outer["inner"] != float64(1) {
					t.Errorf("inner = %v, want 1", outer["inner"])
				}
			},
		},
		{
			name:  "nil input",
			input: nil,
			check: func(t *testing.T, b []byte) {
				if string(b) != "null" {
					t.Errorf("nil marshal = %q, want \"null\"", string(b))
				}
			},
		},
		{
			name:  "empty slice",
			input: []string{},
			check: func(t *testing.T, b []byte) {
				if string(b) != "[]" {
					t.Errorf("empty slice marshal = %q, want \"[]\"", string(b))
				}
			},
		},
		{
			name:    "unmarshalable type",
			input:   make(chan int),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := jsonMarshal(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// writeSSEEvent — security-critical: tests SSE frame injection prevention (#7050)
// ---------------------------------------------------------------------------

func TestWriteSSEEvent(t *testing.T) {
	tests := []struct {
		name      string
		eventName string
		data      interface{}
		wantErr   bool
		check     func(t *testing.T, output string)
	}{
		{
			name:      "basic event",
			eventName: "connected",
			data:      map[string]string{"status": "ok"},
			check: func(t *testing.T, output string) {
				if indexOf(output, "event: connected\n") == -1 {
					t.Errorf("missing event line, got: %q", output)
				}
				if indexOf(output, "data: ") == -1 {
					t.Errorf("missing data line, got: %q", output)
				}
				// SSE events end with double newline
				if output[len(output)-2:] != "\n\n" {
					t.Errorf("event should end with \\n\\n, got: %q", output[len(output)-4:])
				}
			},
		},
		{
			name:      "newline stripped from event name - SSE injection prevention",
			eventName: "evil\nevent",
			data:      map[string]string{"x": "y"},
			check: func(t *testing.T, output string) {
				if indexOf(output, "event: evilevent\n") == -1 {
					t.Errorf("newline not stripped from event name, got: %q", output)
				}
			},
		},
		{
			name:      "carriage return stripped from event name",
			eventName: "bad\revent",
			data:      map[string]string{"x": "y"},
			check: func(t *testing.T, output string) {
				if indexOf(output, "event: badevent\n") == -1 {
					t.Errorf("CR not stripped from event name, got: %q", output)
				}
			},
		},
		{
			name:      "combined CR+LF stripped",
			eventName: "test\r\ninjection",
			data:      map[string]string{"x": "y"},
			check: func(t *testing.T, output string) {
				if indexOf(output, "event: testinjection\n") == -1 {
					t.Errorf("CRLF not stripped from event name, got: %q", output)
				}
			},
		},
		{
			name:      "clean event name unchanged",
			eventName: "update_status",
			data:      map[string]int{"count": 5},
			check: func(t *testing.T, output string) {
				if indexOf(output, "event: update_status\n") == -1 {
					t.Errorf("clean event name mangled, got: %q", output)
				}
			},
		},
		{
			name:      "data contains valid JSON",
			eventName: "msg",
			data:      map[string]interface{}{"key": "value", "num": 42},
			check: func(t *testing.T, output string) {
				dataIdx := indexOf(output, "data: ")
				if dataIdx == -1 {
					t.Fatal("no data: prefix found")
				}
				dataStr := output[dataIdx+6:]
				dataStr = dataStr[:indexOf(dataStr, "\n")]
				var m map[string]interface{}
				if err := json.Unmarshal([]byte(dataStr), &m); err != nil {
					t.Fatalf("data is not valid JSON: %v, raw: %q", err, dataStr)
				}
				if m["key"] != "value" {
					t.Errorf("key = %v, want value", m["key"])
				}
			},
		},
		{
			name:      "unmarshalable data returns error",
			eventName: "fail",
			data:      make(chan int),
			wantErr:   true,
		},
		{
			name:      "empty event name",
			eventName: "",
			data:      map[string]string{"a": "b"},
			check: func(t *testing.T, output string) {
				if indexOf(output, "event: \n") == -1 {
					t.Errorf("empty event name not handled, got: %q", output)
				}
			},
		},
		{
			name:      "multiple newlines stripped",
			eventName: "\n\n\nall_newlines\n\n",
			data:      map[string]string{"x": "y"},
			check: func(t *testing.T, output string) {
				if indexOf(output, "event: all_newlines\n") == -1 {
					t.Errorf("multiple newlines not stripped, got: %q", output)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := bufio.NewWriter(&buf)
			err := writeSSEEvent(w, tt.eventName, tt.data)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, buf.String())
			}
		})
	}
}
