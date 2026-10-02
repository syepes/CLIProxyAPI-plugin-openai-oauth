package plugin

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestRegistrationWireContract(t *testing.T) {
	// Captured before replacing the map-based registration with typed structs.
	data, err := os.ReadFile("testdata/registration.json")
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	// Build-time overrides must remain reflected in registration metadata.
	metadata := want["metadata"].(map[string]any)
	metadata["Version"] = Version
	metadata["GitHubRepository"] = Repository

	p := New(noHost{})
	defer p.Close()
	for _, method := range []string{"plugin.register", "plugin.reconfigure"} {
		t.Run(method, func(t *testing.T) {
			raw := p.Dispatch(method, lifecycle(t, map[string]any{"enabled": false}))
			var envelope struct {
				OK     bool           `json:"ok"`
				Result map[string]any `json:"result"`
			}
			if err := json.Unmarshal(raw, &envelope); err != nil {
				t.Fatal(err)
			}
			if !envelope.OK || !reflect.DeepEqual(envelope.Result, want) {
				t.Fatalf("registration wire contract changed: %s", raw)
			}
		})
	}
}
