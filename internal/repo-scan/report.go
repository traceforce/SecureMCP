package reposcan

type Finding struct {
	Tool     string `json:"tool"`
	Type     string `json:"type"`     // "sca" or "secrets"
	Severity string `json:"severity"` // "critical|high|medium|low|info"
	RuleID   string `json:"rule_id"`
	Title    string `json:"title"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Message  string `json:"message,omitempty"`

	// SCA-specific (optional but useful)
	Package string `json:"package,omitempty"`
	Version string `json:"version,omitempty"`
	Fixed   string `json:"fixed,omitempty"`
}
