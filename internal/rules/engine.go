package rules

import "threatgraph/pkg/models"

// Engine applies IOA rules to events.
type Engine interface {
	Apply(event *models.Event) []models.IoaTag
}

// NoopEngine returns no tags.
type NoopEngine struct{}

// Apply returns an empty tag list.
func (n *NoopEngine) Apply(event *models.Event) []models.IoaTag {
	return nil
}
