package controller

import (
	"net/http"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/web/service"
	"github.com/mhsanaei/3x-ui/v2/web/session"

	"github.com/gin-gonic/gin"
)

// APIController handles the main API routes for the 3x-ui panel, including inbounds and server management.
type APIController struct {
	BaseController
	inboundController  *InboundController
	serverController   *ServerController
	apiTokenController *APITokenController
	apiTokenService    service.APITokenService
	Tgbot              service.Tgbot
}

// NewAPIController creates a new APIController instance and initializes its routes.
func NewAPIController(g *gin.RouterGroup) *APIController {
	a := &APIController{}
	a.initRouter(g)
	return a
}

// checkAPIAuth is a middleware that returns 404 for unauthenticated API requests
// to hide the existence of API endpoints from unauthorized users
func (a *APIController) checkAPIAuth(c *gin.Context) {
	if user := session.GetLoginUser(c); user != nil {
		setAuthUser(c, user)
		c.Next()
		return
	}

	token := extractAPIToken(c)
	if token == "" {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	user, _, err := a.apiTokenService.AuthenticateToken(token)
	if err != nil || user == nil {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	setAuthUser(c, user)
	c.Next()
}

func extractAPIToken(c *gin.Context) string {
	authorization := strings.TrimSpace(c.GetHeader("Authorization"))
	if len(authorization) >= 7 && strings.EqualFold(authorization[:7], "Bearer ") {
		if token := strings.TrimSpace(authorization[7:]); token != "" {
			return token
		}
	}

	return strings.TrimSpace(c.GetHeader("X-API-Key"))
}

// initRouter sets up the API routes for inbounds, server, and other endpoints.
func (a *APIController) initRouter(g *gin.RouterGroup) {
	// Main API group
	api := g.Group("/panel/api")
	api.Use(a.checkAPIAuth)

	// Inbounds API
	inbounds := api.Group("/inbounds")
	a.inboundController = NewInboundController(inbounds)

	// Server API
	server := api.Group("/server")
	a.serverController = NewServerController(server)

	// API token management
	tokens := api.Group("/tokens")
	a.apiTokenController = NewAPITokenController(tokens)

	// Extra routes
	api.GET("/backuptotgbot", a.BackuptoTgbot)
}

// BackuptoTgbot sends a backup of the panel data to Telegram bot admins.
func (a *APIController) BackuptoTgbot(c *gin.Context) {
	a.Tgbot.SendBackupToAdmins()
}
