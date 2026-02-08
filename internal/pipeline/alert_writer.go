package pipeline

import "threatgraph/pkg/models"

// AlertWriter writes alert outputs.
type AlertWriter interface {
	WriteAlerts(alerts []*models.Alert) error
	Close() error
}
