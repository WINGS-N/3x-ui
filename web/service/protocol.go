package service

import "github.com/mhsanaei/3x-ui/v2/database/model"

func isXrayManagedProtocol(protocol model.Protocol) bool {
	return protocol != model.VKTurnProxy
}

func isVKTurnProxyProtocol(protocol model.Protocol) bool {
	return protocol == model.VKTurnProxy
}
