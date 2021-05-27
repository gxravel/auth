package conf

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/tkanos/gonfig"
)

// Configuration contains the environment variables
type Configuration struct {
	Domain           string `env:"DOMAIN"`
	Port             int    `env:"PORT"`
	ConnectionString string `env:"DEV_MYSQL"`
	RedisDSN         string `env:"REDIS_DSN"`
}

type JWTConfiguration struct {
	JWTAccess  string `env:"JWT_ACCESS"`
	JWTRefresh string `env:"JWT_REFRESH"`
}

func getPath() (filePath string) {
	env := os.Getenv("ENV")
	if len(env) == 0 {
		env = "development"
	}
	filename := []string{"config.", env, ".json"}
	_, dirname, _, _ := runtime.Caller(0)
	filePath = filepath.Join(filepath.Dir(dirname), strings.Join(filename, ""))
	return
}

// Get returns the config.
func Get() (config *Configuration) {
	config = &Configuration{}
	err := gonfig.GetConf(getPath(), config)
	if err != nil {
		log.Fatal(err)
	}
	return
}

// GetJWT returns the JWT config.
func GetJWT() (config *JWTConfiguration) {
	config = &JWTConfiguration{}
	err := gonfig.GetConf(getPath(), config)
	if err != nil {
		log.Fatal(err)
	}
	return
}
