package pipeline

import "threatgraph/pkg/models"

// IOAWriter writes lightweight IOA time-series events.
type IOAWriter interface {
	WriteEvents(events []*models.IOAEvent) error
	Close() error
}
