package cache

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type RedisCache struct {
	client  *redis.Client
	ttlList time.Duration
	ttlItem time.Duration
	logger  *zap.Logger
}

func NewRedisCache(client *redis.Client, ttlList, ttlItem int, logger *zap.Logger) *RedisCache {
	return &RedisCache{
		client:  client,
		ttlList: time.Duration(ttlList) * time.Second,
		ttlItem: time.Duration(ttlItem) * time.Second,
		logger:  logger,
	}
}

func (r *RedisCache) GetDocumentList(ctx context.Context, key string) ([]byte, error) {
	return r.client.Get(ctx, key).Bytes()
}

func (r *RedisCache) SetDocumentList(ctx context.Context, key string, data []byte) error {
	r.logger.Info("cache set",
		zap.String("key", key),
		zap.Int("size", len(data)),
	) //test
	err := r.client.Set(ctx, key, data, r.ttlList).Err()
	if err != nil {
		r.logger.Error("cache set error",
			zap.String("key", key),
			zap.Error(err),
		)
	}
	return err
}

func (r *RedisCache) GetDocumentItem(ctx context.Context, key string) ([]byte, error) {
	return r.client.Get(ctx, key).Bytes()
}

func (r *RedisCache) SetDocumentItem(ctx context.Context, key string, data []byte) error {
	return r.client.Set(ctx, key, data, r.ttlItem).Err()
}

// InvalidateDocumentLists инвалидирует кэши списков документов.
// Используем Scan для поиска ключей по паттерну
func (r *RedisCache) InvalidateDocumentLists(ctx context.Context) error {
	iter := r.client.Scan(ctx, 0, "doclist:*", 0).Iterator()
	for iter.Next(ctx) {
		err := r.client.Del(ctx, iter.Val()).Err()
		if err != nil {
			// Логируем, но продолжаем
			r.logger.Error("Failed to delete cache key", zap.String("cache key", iter.Val()), zap.Error(err))
		}
	}
	return iter.Err()
}

// InvalidateDocumentItem инвалидирует кэш конкретного документа.
func (r *RedisCache) InvalidateDocumentItem(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}

// BlacklistToken добавляет токен (его хэш) в блэклист с заданным TTL.
func (r *RedisCache) BlacklistToken(ctx context.Context, tokenHash string, ttl time.Duration) error {
	key := "blacklist:" + tokenHash
	return r.client.Set(ctx, key, "1", ttl).Err()
}

// IsTokenBlacklisted проверяет, находится ли токен (его хэш) в блэклисте.
func (r *RedisCache) IsTokenBlacklisted(ctx context.Context, tokenHash string) (bool, error) {
	key := "blacklist:" + tokenHash
	// EXISTS проверяет наличие ключа
	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}
