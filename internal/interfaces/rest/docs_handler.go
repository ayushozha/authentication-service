package rest

import (
	_ "embed"
	"net/http"
)

//go:embed openapi.yaml
var openapiSpec []byte

func DocsSpecHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	w.Write(openapiSpec)
}

func DocsUIHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(docsHTML))
}

const docsHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Authentication Service — API Reference</title>
  <meta name="description" content="API reference for the multi-tenant Authentication Service" />
  <style>
    body { margin: 0; }
  </style>
</head>
<body>
  <script
    id="api-reference"
    data-url="/docs/openapi.yaml"
    data-configuration='{
      "theme": "kepler",
      "layout": "modern",
      "darkMode": true,
      "hiddenClients": ["cohttp"],
      "defaultHttpClient": { "targetKey": "shell", "clientKey": "curl" },
      "metaData": {
        "title": "Authentication Service API"
      },
      "authentication": {
        "preferredSecurityScheme": "ApiKeyAuth"
      }
    }'
  ></script>
  <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
</body>
</html>
`
