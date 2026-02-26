package pipeline

import "threatgraph/pkg/models"

// VertexStateWriter updates a derived per-vertex state index.
type VertexStateWriter interface {
	WriteRows(rows []*models.AdjacencyRow) error
	Close() error
}
