package config

import (
	"fmt"

	"github.com/joho/godotenv"
)

type Env struct {
	EnvMap map[string]string
}

func ReadEnv() (Env, error) {
	envMap, err := godotenv.Read("./.env")
	if err != nil {
		return Env{}, fmt.Errorf("error read env: %w", err)
	}
	return Env{EnvMap: envMap}, nil
}
