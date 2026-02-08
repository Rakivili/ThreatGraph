package models

// IoaTag represents a rule match annotation.
type IoaTag struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Tactic    string `json:"tactic,omitempty"`
	Technique string `json:"technique,omitempty"`
}
