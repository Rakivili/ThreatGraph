package pipeline

import "threatgraph/internal/analyzer"

// IncidentWriter writes analyzed incidents.
type IncidentWriter interface {
	WriteIncidents(incidents []analyzer.Incident) error
	Close() error
}
