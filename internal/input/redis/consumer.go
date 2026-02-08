package redis

import (
	"context"
	"fmt"
	"time"

	redis "github.com/redis/go-redis/v9"
)

// Config configures the Redis consumer.
type Config struct {
	Addr         string
	Password     string
	DB           int
	Key          string
	BlockTimeout time.Duration
}

// Consumer wraps a Redis list popper.
type Consumer struct {
	client       *redis.Client
	key          string
	blockTimeout time.Duration
}

// NewConsumer creates a Redis consumer for list-based queues.
func NewConsumer(cfg Config) (*Consumer, error) {
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:6379"
	}
	if cfg.Key == "" {
		return nil, fmt.Errorf("redis key is required")
	}
	if cfg.BlockTimeout == 0 {
		cfg.BlockTimeout = 5 * time.Second
	}

	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	return &Consumer{
		client:       client,
		key:          cfg.Key,
		blockTimeout: cfg.BlockTimeout,
	}, nil
}

// Pop pops one message from the list.
func (c *Consumer) Pop(ctx context.Context) ([]byte, error) {
	res, err := c.client.BLPop(ctx, c.blockTimeout, c.key).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(res) < 2 {
		return nil, nil
	}
	return []byte(res[1]), nil
}

// Close closes the consumer.
func (c *Consumer) Close() error {
	return c.client.Close()
}
