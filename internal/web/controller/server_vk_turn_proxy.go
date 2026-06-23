package controller

import "github.com/gin-gonic/gin"

func (a *ServerController) initVKTurnProxyRouter(g *gin.RouterGroup) {
	g.POST("/vk-turn-proxy/logs/:count", a.getVKTurnProxyLogs)
	g.GET("/vk-turn-proxy/versions", a.getVKTurnProxyVersions)
	g.POST("/vk-turn-proxy/start", a.startVKTurnProxyService)
	g.POST("/vk-turn-proxy/stop", a.stopVKTurnProxyService)
	g.POST("/vk-turn-proxy/restart", a.restartVKTurnProxyService)
	g.POST("/vk-turn-proxy/install/:version", a.installVKTurnProxy)
	g.POST("/vk-turn-proxy/upload", a.uploadVKTurnProxyBinary)
}

func (a *ServerController) getVKTurnProxyLogs(c *gin.Context) {
	logs := a.serverService.GetVKTurnProxyLogs(c.Param("count"), c.PostForm("level"))
	jsonObj(c, logs, nil)
}

func (a *ServerController) getVKTurnProxyVersions(c *gin.Context) {
	versions, err := a.serverService.GetVKTurnProxyVersions()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "getVersion"), err)
		return
	}
	jsonObj(c, versions, nil)
}

func (a *ServerController) startVKTurnProxyService(c *gin.Context) {
	jsonMsg(c, "vk-turn-proxy", a.serverService.StartVKTurnProxyService())
}

func (a *ServerController) stopVKTurnProxyService(c *gin.Context) {
	jsonMsg(c, "vk-turn-proxy", a.serverService.StopVKTurnProxyService())
}

func (a *ServerController) restartVKTurnProxyService(c *gin.Context) {
	jsonMsg(c, "vk-turn-proxy", a.serverService.RestartVKTurnProxyService())
}

func (a *ServerController) installVKTurnProxy(c *gin.Context) {
	jsonMsg(c, "vk-turn-proxy", a.serverService.UpdateVKTurnProxy(c.Param("version")))
}

func (a *ServerController) uploadVKTurnProxyBinary(c *gin.Context) {
	file, _, err := c.Request.FormFile("binary")
	if err != nil {
		jsonMsg(c, "vk-turn-proxy", err)
		return
	}
	defer file.Close()
	jsonMsg(c, "vk-turn-proxy", a.serverService.UploadVKTurnProxyBinary(file))
}
