package openapi

import _ "embed"

// PanelAPISpecYAML contains the bearer-authenticated panel OpenAPI specification.
//
//go:embed panel-api.yaml
var panelAPISpecYAML []byte

func PanelAPISpecYAML() []byte {
	cloned := make([]byte, len(panelAPISpecYAML))
	copy(cloned, panelAPISpecYAML)
	return cloned
}
