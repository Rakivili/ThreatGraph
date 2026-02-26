package vertexstate

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	redis "github.com/redis/go-redis/v9"

	"threatgraph/pkg/models"
)

// RedisConfig configures Redis access for vertex-state persistence.
type RedisConfig struct {
	Addr      string
	Password  string
	DB        int
	KeyPrefix string
}

// VertexState stores compact per-vertex counters for periodic IIP analysis.
type VertexState struct {
	Host              string    `json:"host"`
	VertexID          string    `json:"vertex_id"`
	IOACount          int64     `json:"ioa_count"`
	FirstIOATimestamp time.Time `json:"first_ioa_ts,omitempty"`
	LastIOATimestamp  time.Time `json:"last_ioa_ts,omitempty"`
	UpdatedAt         time.Time `json:"updated_at,omitempty"`
}

// IIPCandidate is a lightweight state-driven IIP approximation for periodic analysis.
type IIPCandidate struct {
	Host              string    `json:"host"`
	VertexID          string    `json:"vertex_id"`
	IOACount          int64     `json:"ioa_count"`
	FirstIOATimestamp time.Time `json:"first_ioa_ts,omitempty"`
	LastIOATimestamp  time.Time `json:"last_ioa_ts,omitempty"`
	LikelyIIP         bool      `json:"likely_iip"`
}

// RedisStore manages writer/reader operations over vertex-state keys.
type RedisStore struct {
	client *redis.Client
	prefix string
}

// NewRedisStore constructs a Redis-backed vertex-state store.
func NewRedisStore(cfg RedisConfig) (*RedisStore, error) {
	if strings.TrimSpace(cfg.Addr) == "" {
		cfg.Addr = "127.0.0.1:6379"
	}
	if strings.TrimSpace(cfg.KeyPrefix) == "" {
		cfg.KeyPrefix = "threatgraph:vertex_state"
	}

	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("ping redis vertex-state: %w", err)
	}

	return &RedisStore{client: client, prefix: strings.TrimSpace(cfg.KeyPrefix)}, nil
}

// WriteRows updates vertex-state from alert-tagged edge rows.
func (s *RedisStore) WriteRows(rows []*models.AdjacencyRow) error {
	if len(rows) == 0 {
		return nil
	}
	ctx := context.Background()
	pipe := s.client.Pipeline()

	for _, row := range rows {
		if row == nil || row.RecordType != "edge" || len(row.IoaTags) == 0 {
			continue
		}
		host := strings.TrimSpace(row.Hostname)
		if host == "" {
			host = strings.TrimSpace(row.AgentID)
		}
		if host == "" {
			host = "unknown"
		}
		vertex := strings.TrimSpace(row.VertexID)
		if vertex == "" {
			continue
		}
		member := encodeMember(host, vertex)
		ts := float64(row.Timestamp.Unix())

		nowUnix := time.Now().Unix()
		stateKey := s.vertexKey(host, vertex)
		pipe.HSet(ctx, stateKey,
			"host", host,
			"vertex_id", vertex,
			"updated_at", strconv.FormatInt(nowUnix, 10),
		)
		pipe.HIncrBy(ctx, stateKey, "ioa_count", int64(len(row.IoaTags)))

		pipe.ZAddArgs(ctx, s.firstSetKey(), redis.ZAddArgs{LT: true, Members: []redis.Z{{Score: ts, Member: member}}})
		pipe.ZAddArgs(ctx, s.lastSetKey(), redis.ZAddArgs{GT: true, Members: []redis.Z{{Score: ts, Member: member}}})
		pipe.ZAdd(ctx, s.dirtySetKey(), redis.Z{Score: float64(nowUnix), Member: member})
	}

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("update vertex-state redis keys: %w", err)
	}
	return nil
}

// FetchDirtySince returns vertex states updated since the specified unix timestamp.
func (s *RedisStore) FetchDirtySince(since time.Time, limit int64) ([]VertexState, error) {
	if limit <= 0 {
		limit = 1000
	}
	ctx := context.Background()
	members, err := s.client.ZRangeByScoreWithScores(ctx, s.dirtySetKey(), &redis.ZRangeBy{
		Min:    fmt.Sprintf("%d", since.Unix()),
		Max:    "+inf",
		Offset: 0,
		Count:  limit,
	}).Result()
	if err != nil {
		return nil, fmt.Errorf("read dirty vertex-state members: %w", err)
	}
	if len(members) == 0 {
		return nil, nil
	}

	states := make([]VertexState, 0, len(members))
	for _, z := range members {
		member, ok := z.Member.(string)
		if !ok || member == "" {
			continue
		}
		host, vertex, ok := decodeMember(member)
		if !ok {
			continue
		}

		stateKey := s.vertexKey(host, vertex)
		hash, err := s.client.HGetAll(ctx, stateKey).Result()
		if err != nil || len(hash) == 0 {
			continue
		}

		ioaCount, _ := strconv.ParseInt(hash["ioa_count"], 10, 64)
		updatedUnix, _ := strconv.ParseInt(hash["updated_at"], 10, 64)
		first, _ := s.client.ZScore(ctx, s.firstSetKey(), member).Result()
		last, _ := s.client.ZScore(ctx, s.lastSetKey(), member).Result()

		st := VertexState{
			Host:     host,
			VertexID: vertex,
			IOACount: ioaCount,
		}
		if updatedUnix > 0 {
			st.UpdatedAt = time.Unix(updatedUnix, 0).UTC()
		}
		if first > 0 {
			st.FirstIOATimestamp = time.Unix(int64(first), 0).UTC()
		}
		if last > 0 {
			st.LastIOATimestamp = time.Unix(int64(last), 0).UTC()
		}
		states = append(states, st)
	}

	return states, nil
}

// BuildIIPCandidates converts vertex states to lightweight IIP candidates.
func BuildIIPCandidates(states []VertexState) []IIPCandidate {
	out := make([]IIPCandidate, 0, len(states))
	for _, st := range states {
		if st.IOACount <= 0 || st.FirstIOATimestamp.IsZero() {
			continue
		}
		likely := st.LastIOATimestamp.IsZero() || st.FirstIOATimestamp.Equal(st.LastIOATimestamp) || st.IOACount == 1
		out = append(out, IIPCandidate{
			Host:              st.Host,
			VertexID:          st.VertexID,
			IOACount:          st.IOACount,
			FirstIOATimestamp: st.FirstIOATimestamp,
			LastIOATimestamp:  st.LastIOATimestamp,
			LikelyIIP:         likely,
		})
	}
	return out
}

// Close closes Redis resources.
func (s *RedisStore) Close() error {
	if s == nil || s.client == nil {
		return nil
	}
	return s.client.Close()
}

func (s *RedisStore) vertexKey(host, vertex string) string {
	return s.prefix + ":vertex:" + host + ":" + vertex
}

func (s *RedisStore) firstSetKey() string {
	return s.prefix + ":first"
}

func (s *RedisStore) lastSetKey() string {
	return s.prefix + ":last"
}

func (s *RedisStore) dirtySetKey() string {
	return s.prefix + ":dirty"
}

func encodeMember(host, vertex string) string {
	return host + "|" + vertex
}

func decodeMember(member string) (string, string, bool) {
	parts := strings.SplitN(member, "|", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}
