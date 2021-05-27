package utils

const (
	LastVersion = "v1"
)

var (
	AllowedOrigins = []string{"http://localhost:3000"}
	AllowedMethods = []string{"POST", "OPTIONS"}
	AllowedHeaders = []string{"Accept", "Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token", "Authorization"}
)
