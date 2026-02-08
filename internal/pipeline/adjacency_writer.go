package pipeline

import "threatgraph/pkg/models"

// AdjacencyWriter writes adjacency rows.
type AdjacencyWriter interface {
	WriteRows(rows []*models.AdjacencyRow) error
	Close() error
}
