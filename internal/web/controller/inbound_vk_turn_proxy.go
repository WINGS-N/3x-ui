package controller

import (
	"strconv"

	"github.com/gin-gonic/gin"
)

func (a *InboundController) initVKTurnProxyRouter(g *gin.RouterGroup) {
	g.GET("/:id/vk-turn-proxy/peer-options", a.getVKTurnProxyPeerOptions)
	g.GET("/:id/vk-turn-proxy/export/:clientId", a.exportVKTurnProxyClient)
	g.GET("/:id/vk-turn-proxy/export-all", a.exportAllVKTurnProxyClients)
	g.POST("/:id/vk-turn-proxy/clients/:clientId/enable", a.setVKTurnProxyClientEnable)
	g.GET("/:id/wireguard/allowedIpConflicts", a.getWireguardAllowedIPConflicts)
	g.POST("/:id/wireguard/fixAllowedIpConflicts", a.fixWireguardAllowedIPConflicts)
}

func (a *InboundController) getVKTurnProxyPeerOptions(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "vk-turn-proxy", err)
		return
	}
	options, err := a.inboundService.GetVKTurnProxyPeerOptions(id)
	if err != nil {
		jsonMsg(c, "vk-turn-proxy", err)
		return
	}
	jsonObj(c, options, nil)
}

func (a *InboundController) exportVKTurnProxyClient(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "vk-turn-proxy", err)
		return
	}
	link, err := a.inboundService.ExportVKTurnProxyClient(id, c.Param("clientId"), resolveHost(c))
	if err != nil {
		jsonMsg(c, "vk-turn-proxy", err)
		return
	}
	jsonObj(c, link, nil)
}

func (a *InboundController) exportAllVKTurnProxyClients(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "vk-turn-proxy", err)
		return
	}
	clients, err := a.inboundService.ExportAllVKTurnProxyClients(id, resolveHost(c))
	if err != nil {
		jsonMsg(c, "vk-turn-proxy", err)
		return
	}
	jsonObj(c, clients, nil)
}

func (a *InboundController) setVKTurnProxyClientEnable(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "vk-turn-proxy", err)
		return
	}
	needRestart, err := a.inboundService.SetVKTurnProxyClientEnable(id, c.Param("clientId"), c.PostForm("enable") == "true")
	if err != nil {
		jsonMsg(c, "vk-turn-proxy", err)
		return
	}
	jsonMsgObj(c, "vk-turn-proxy", needRestart, nil)
}

func (a *InboundController) getWireguardAllowedIPConflicts(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "wireguard", err)
		return
	}
	conflicts, err := a.inboundService.WireguardAllowedIPConflicts(id)
	if err != nil {
		jsonMsg(c, "wireguard", err)
		return
	}
	jsonObj(c, conflicts, nil)
}

func (a *InboundController) fixWireguardAllowedIPConflicts(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "wireguard", err)
		return
	}
	fixed, err := a.inboundService.FixWireguardAllowedIPConflicts(id)
	if err != nil {
		jsonMsg(c, "wireguard", err)
		return
	}
	jsonObj(c, fixed, nil)
}
