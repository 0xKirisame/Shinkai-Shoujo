package generator

import (
	"io"

	"gopkg.in/yaml.v3"

	"github.com/0xKirisame/shinkai-shoujo/internal/correlation"
)

// YAMLGenerator produces YAML-formatted reports.
type YAMLGenerator struct{}

// Generate writes a YAML report to w.
// Reuses the JSONReport structure (yaml tags are already defined there).
func (g *YAMLGenerator) Generate(results []correlation.Result, w io.Writer) error {
	report := buildReport(results)
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if err := enc.Encode(report); err != nil {
		return err
	}
	return enc.Close()
}
