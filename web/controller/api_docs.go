package controller

import (
	"net/http"
	"strings"

	openapidoc "github.com/mhsanaei/3x-ui/v2/openapi"

	"github.com/gin-gonic/gin"
)

func (a *XUIController) apiDocs(c *gin.Context) {
	basePath := c.GetString("base_path")
	c.HTML(http.StatusOK, "api_docs.html", getContext(gin.H{
		"title_text": "3x-ui API Docs",
		"spec_url":   basePath + "api/docs/openapi.yaml",
		"server_url": getRequestOrigin(c) + normalizeBasePathForDocs(basePath),
	}))
}

func (a *XUIController) apiDocsSpec(c *gin.Context) {
	c.Data(http.StatusOK, "application/yaml; charset=utf-8", openapidoc.PanelAPISpecYAML())
}

func getRequestOrigin(c *gin.Context) string {
	return getRequestScheme(c) + "://" + getRequestHost(c)
}

func getRequestScheme(c *gin.Context) string {
	if proto := strings.TrimSpace(c.GetHeader("X-Forwarded-Proto")); proto != "" {
		return strings.ToLower(strings.TrimSpace(strings.Split(proto, ",")[0]))
	}
	if c.Request.TLS != nil {
		return "https"
	}
	return "http"
}

func getRequestHost(c *gin.Context) string {
	if host := strings.TrimSpace(c.GetHeader("X-Forwarded-Host")); host != "" {
		return strings.TrimSpace(strings.Split(host, ",")[0])
	}
	return c.Request.Host
}

func normalizeBasePathForDocs(basePath string) string {
	basePath = strings.TrimSpace(basePath)
	if basePath == "" || basePath == "/" {
		return ""
	}
	basePath = "/" + strings.Trim(basePath, "/")
	return strings.TrimRight(basePath, "/")
}
