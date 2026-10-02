package plugin

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

type sseParser struct {
	buffer    []byte
	terminal  bool
	responses bool
}

func newSSEParser(format string) *sseParser {
	return &sseParser{responses: format == "openai-response" || format == "responses" || format == "codex"}
}

// Feed splits complete SSE events even when HTTP chunks split lines or UTF-8.
// Streaming is bounded by event size, not total completion length.
func (p *sseParser) Feed(data []byte, eof bool) ([][]byte, error) {
	p.buffer = append(p.buffer, data...)
	var out [][]byte
	for {
		end := bytes.Index(p.buffer, []byte("\n\n"))
		width := 2
		if cr := bytes.Index(p.buffer, []byte("\r\n\r\n")); cr >= 0 && (end < 0 || cr < end) {
			end = cr
			width = 4
		}
		if end < 0 {
			break
		}
		if end > 8<<20 {
			return nil, errors.New("upstream SSE event exceeds 8 MiB")
		}
		event := bytes.Clone(p.buffer[:end+width])
		p.buffer = p.buffer[end+width:]
		var payload []string
		var eventType string
		for _, line := range strings.Split(string(event), "\n") {
			line = strings.TrimSuffix(line, "\r")
			if v, ok := strings.CutPrefix(line, "event:"); ok {
				eventType = strings.TrimSpace(v)
			}
			if v, ok := strings.CutPrefix(line, "data:"); ok {
				payload = append(payload, strings.TrimPrefix(v, " "))
			}
		}
		value := strings.Join(payload, "\n")
		if eventType == "error" || eventType == "response.failed" {
			return nil, errors.New("upstream reported a streaming API error")
		}
		if value == "[DONE]" && !p.responses {
			p.terminal = true
		}
		if value != "" && value != "[DONE]" {
			var object struct {
				Type  string          `json:"type"`
				Error json.RawMessage `json:"error"`
			}
			if json.Unmarshal([]byte(value), &object) != nil {
				return nil, errors.New("upstream SSE data is not a JSON object")
			} else {
				if object.Type == "error" || object.Type == "response.failed" || len(object.Error) > 0 && string(object.Error) != "null" {
					return nil, errors.New("upstream reported a streaming API error")
				}
				if object.Type == "response.completed" || object.Type == "response.incomplete" {
					p.terminal = true
				}
			}
		}
		out = append(out, event)
	}
	if len(p.buffer) > 8<<20 {
		return nil, errors.New("upstream SSE event exceeds 8 MiB")
	}
	if eof && len(bytes.TrimSpace(p.buffer)) > 0 {
		return nil, errors.New("upstream SSE event was truncated")
	}
	return out, nil
}
