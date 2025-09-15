package config

import (
	"log"

	"github.com/spf13/viper"
)

type Config struct {
	ServerPort   string `mapstructure:"SERVER_PORT"`
	DBHost       string `mapstructure:"DB_HOST"`
	DBPort       string `mapstructure:"DB_PORT"`
	DBUser       string `mapstructure:"DB_USER"`
	DBPassword   string `mapstructure:"DB_PASSWORD"`
	DBName       string `mapstructure:"DB_NAME"`
	DBSSLMode    string `mapstructure:"DB_SSLMODE"`
	RedisAddr    string `mapstructure:"REDIS_ADDR"`
	RedisPass    string `mapstructure:"REDIS_PASSWORD"`
	RedisDB      int    `mapstructure:"REDIS_DB"`
	JWTSecret    string `mapstructure:"JWT_SECRET"`
	AdminToken   string `mapstructure:"ADMIN_TOKEN"`
	CacheTTLList int    `mapstructure:"CACHE_TTL_DOC_LIST"`
	CacheTTLItem int    `mapstructure:"CACHE_TTL_DOC_ITEM"`
}

func LoadConfig(path string) (config Config, err error) {
	viper.AddConfigPath(path)
	viper.SetConfigName(".env")
	viper.SetConfigType("env")

	viper.AutomaticEnv()

	err = viper.ReadInConfig()
	if err != nil {
		log.Fatalf("Error reading config file: %s", err)
	}

	err = viper.Unmarshal(&config)
	return
}
