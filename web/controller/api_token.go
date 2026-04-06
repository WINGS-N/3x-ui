package controller

import (
	"strconv"

	"github.com/mhsanaei/3x-ui/v2/web/service"

	"github.com/gin-gonic/gin"
)

// createAPITokenForm describes the optional input for naming a new API token.
type createAPITokenForm struct {
	Name string `json:"name" form:"name"`
}

// APITokenController manages API tokens for panel API authentication.
type APITokenController struct {
	apiTokenService service.APITokenService
}

// NewAPITokenController creates a new APITokenController and registers its routes.
func NewAPITokenController(g *gin.RouterGroup) *APITokenController {
	a := &APITokenController{}
	a.initRouter(g)
	return a
}

func (a *APITokenController) initRouter(g *gin.RouterGroup) {
	g.GET("/list", a.getTokens)
	g.POST("/create", a.createToken)
	g.POST("/del/:id", a.delToken)
}

func (a *APITokenController) getTokens(c *gin.Context) {
	user := getAuthUser(c)
	if user == nil {
		c.AbortWithStatus(404)
		return
	}

	tokens, err := a.apiTokenService.GetTokens(user.Id)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getSettings"), err)
		return
	}
	jsonObj(c, tokens, nil)
}

func (a *APITokenController) createToken(c *gin.Context) {
	user := getAuthUser(c)
	if user == nil {
		c.AbortWithStatus(404)
		return
	}

	form := &createAPITokenForm{}
	if err := c.ShouldBind(form); err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.apiTokenCreate"), err)
		return
	}

	tokenInfo, token, err := a.apiTokenService.CreateToken(user.Id, form.Name)
	jsonMsgObj(c, I18nWeb(c, "pages.settings.toasts.apiTokenCreate"), gin.H{
		"token": token,
		"info":  tokenInfo,
	}, err)
}

func (a *APITokenController) delToken(c *gin.Context) {
	user := getAuthUser(c)
	if user == nil {
		c.AbortWithStatus(404)
		return
	}

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.apiTokenDelete"), err)
		return
	}

	err = a.apiTokenService.DeleteToken(user.Id, id)
	jsonMsgObj(c, I18nWeb(c, "pages.settings.toasts.apiTokenDelete"), id, err)
}
