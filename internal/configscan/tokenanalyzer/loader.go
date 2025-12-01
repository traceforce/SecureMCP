package tokenanalyzer

import (
	_ "embed"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

//go:embed token_rules.yaml
var defaultRulesYAML []byte

// LoadRuleSetFromYAML reads a YAML file (rules.yaml) into a set of rules.
func LoadRuleSetFromYAML(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules yaml: %w", err)
	}
	var rs RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("unmarshal rules yaml: %w", err)
	}
	return rs.Rules, nil
}

func LoadDefaultRuleSet() ([]Rule, error) {
	var rs RuleSet
	if err := yaml.Unmarshal(defaultRulesYAML, &rs); err != nil {
		return nil, fmt.Errorf("unmarshal rules yaml: %w", err)
	}
	return rs.Rules, nil
}
