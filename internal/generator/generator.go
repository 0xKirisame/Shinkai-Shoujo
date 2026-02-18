package generator

import (
	"fmt"
	"io"

	"github.com/0xKirisame/shinkai-shoujo/internal/correlation"
)

// Generator produces output from correlation results in a specific format.
type Generator interface {
	Generate(results []correlation.Result, w io.Writer) error
}

// New returns a Generator for the given format string.
// Supported formats: "terraform", "json", "yaml".
func New(format string) (Generator, error) {
	switch format {
	case "terraform":
		return &TerraformGenerator{}, nil
	case "json":
		return &JSONGenerator{}, nil
	case "yaml":
		return &YAMLGenerator{}, nil
	default:
		return nil, fmt.Errorf("unknown output format %q (supported: terraform, json, yaml)", format)
	}
}
