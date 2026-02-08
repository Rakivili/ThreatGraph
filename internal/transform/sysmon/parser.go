package sysmon

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"threatgraph/internal/logger"
	"threatgraph/pkg/models"
)

// Parse converts a winlogbeat Sysmon event into a normalized Event.
func Parse(data []byte) (*models.Event, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	event := &models.Event{
		Fields: make(map[string]interface{}),
		Raw:    raw,
	}

	if ts := getString(raw, "@timestamp"); ts != "" {
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			event.Timestamp = t
		} else if t, err := time.Parse(time.RFC3339, ts); err == nil {
			event.Timestamp = t
		}
	}

	event.EventID = getInt(raw, "winlog.event_id", "event.code", "event_id")
	event.AgentID = getString(raw, "agent.id", "agent_id")
	event.Hostname = getString(raw, "host.name", "host.hostname", "hostname")
	event.Channel = getString(raw, "winlog.channel")
	event.RecordID = getString(raw, "winlog.record_id")

	if v, ok := getPath(raw, "winlog.event_data"); ok {
		if m, ok := v.(map[string]interface{}); ok {
			event.Fields = m
		}
	}
	if len(event.Fields) == 0 {
		logger.Warnf("Missing winlog.event_data (event_id=%d, record_id=%s)", event.EventID, event.RecordID)
	}
	return event, nil
}

func getString(root map[string]interface{}, paths ...string) string {
	for _, path := range paths {
		if v, ok := getPath(root, path); ok {
			switch val := v.(type) {
			case string:
				return val
			case fmt.Stringer:
				return val.String()
			case int:
				return fmt.Sprintf("%d", val)
			case int64:
				return fmt.Sprintf("%d", val)
			case float64:
				if val == float64(int64(val)) {
					return fmt.Sprintf("%d", int64(val))
				}
				return fmt.Sprintf("%f", val)
			}
		}
	}
	return ""
}

func getInt(root map[string]interface{}, paths ...string) int {
	for _, path := range paths {
		if v, ok := getPath(root, path); ok {
			switch val := v.(type) {
			case int:
				return val
			case int64:
				return int(val)
			case float64:
				return int(val)
			case string:
				if val == "" {
					continue
				}
				var parsed int
				_, err := fmt.Sscanf(val, "%d", &parsed)
				if err == nil {
					return parsed
				}
			}
		}
	}
	return 0
}

func getPath(root map[string]interface{}, path string) (interface{}, bool) {
	parts := strings.Split(path, ".")
	var current interface{} = root
	for _, part := range parts {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil, false
		}
		v, ok := m[part]
		if !ok {
			return nil, false
		}
		current = v
	}
	return current, true
}
