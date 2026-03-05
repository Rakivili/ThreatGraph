package clickhouse

import (
	"testing"
	"time"
)

func TestParseTimestampLocalNaiveString(t *testing.T) {
	v := "2026-03-05 01:15:01.159"
	got, err := parseTimestamp(v)
	if err != nil {
		t.Fatalf("parseTimestamp returned error: %v", err)
	}

	wantLocal, err := time.ParseInLocation("2006-01-02 15:04:05.000", v, time.Local)
	if err != nil {
		t.Fatalf("failed to parse expected local time: %v", err)
	}
	if !got.Equal(wantLocal) {
		t.Fatalf("unexpected parsed timestamp: got=%s want=%s", got.Format(time.RFC3339Nano), wantLocal.Format(time.RFC3339Nano))
	}
}

func TestParseTimestampRFC3339Z(t *testing.T) {
	v := "2026-03-04T17:15:01.159Z"
	got, err := parseTimestamp(v)
	if err != nil {
		t.Fatalf("parseTimestamp returned error: %v", err)
	}
	want := time.Date(2026, 3, 4, 17, 15, 1, 159000000, time.UTC).In(time.Local)
	if !got.Equal(want) {
		t.Fatalf("unexpected parsed timestamp: got=%s want=%s", got.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}
}
