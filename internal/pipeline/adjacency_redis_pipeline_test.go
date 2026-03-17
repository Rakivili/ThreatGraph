package pipeline

import (
	"testing"

	"threatgraph/pkg/models"
)

func TestOfflineEDRIOATags(t *testing.T) {
	e := &models.Event{Raw: map[string]interface{}{
		"risk_level":       "high",
		"alert_name":       "可疑注册表修改",
		"attack.tactic":    "persistence",
		"attack.technique": "T1547",
	}}
	tags := offlineEDRIOATags(e)
	if len(tags) != 1 {
		t.Fatalf("expected one tag, got %d", len(tags))
	}
	if tags[0].Name != "可疑注册表修改" || tags[0].Severity != "high" || tags[0].Tactic != "persistence" || tags[0].Technique != "T1547" {
		t.Fatalf("unexpected tag: %#v", tags[0])
	}
}

func TestOfflineEDRIOATagsSkipsNotice(t *testing.T) {
	e := &models.Event{Raw: map[string]interface{}{
		"risk_level": "notice",
		"alert_name": "x",
	}}
	if tags := offlineEDRIOATags(e); len(tags) != 0 {
		t.Fatalf("expected no tags for notice, got %d", len(tags))
	}
}
