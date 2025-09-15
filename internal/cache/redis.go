package cache

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisCache struct {
	client  *redis.Client
	ttlList time.Duration
	ttlItem time.Duration
}

func NewRedisCache(client *redis.Client, ttlList, ttlItem int) *RedisCache {
	return &RedisCache{
		client:  client,
		ttlList: time.Duration(ttlList) * time.Second,
		ttlItem: time.Duration(ttlItem) * time.Second,
	}
}

func (r *RedisCache) GetDocumentList(ctx context.Context, key string) ([]byte, error) {
	return r.client.Get(ctx, key).Bytes()
}

func (r *RedisCache) SetDocumentList(ctx context.Context, key string, data []byte) error {
	return r.client.Set(ctx, key, data, r.ttlList).Err()
}

func (r *RedisCache) GetDocumentItem(ctx context.Context, key string) ([]byte, error) {
	return r.client.Get(ctx, key).Bytes()
}

func (r *RedisCache) SetDocumentItem(ctx context.Context, key string, data []byte) error {
	return r.client.Set(ctx, key, data, r.ttlItem).Err()
}

// Инвалидация может быть сложной. Простой способ: инвалидировать все списки.
// Более точный: использовать ключи с префиксами и сканировать их.
func (r *RedisCache) InvalidateDocumentLists(ctx context.Context) error {
	// Это грубый способ. В production лучше использовать тэги или префиксы.
	// Например, все ключи списков могут начинаться с "doclist:"
	iter := r.client.Scan(ctx, 0, "doclist:*", 0).Iterator()
	for iter.Next(ctx) {
		err := r.client.Del(ctx, iter.Val()).Err()
		if err != nil {
			// Логируем, но продолжаем
			// log.Printf("Failed to delete cache key %s: %v", iter.Val(), err)
		}
	}
	return iter.Err()
}

func (r *RedisCache) InvalidateDocumentItem(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}

// Методы для работы с токенами (если нужно кэшировать активные токены или блэклист)
// func (r *RedisCache) IsTokenBlacklisted(ctx context.Context, token string) (bool, error) { ... }
// func (r *RedisCache) BlacklistToken(ctx context.Context, token string, exp time.Duration) error { ... }
