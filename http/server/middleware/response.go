package middleware

import (
	"github.com/flash-go/flash/http/server"
)

func ErrorResponse(m server.ErrorResponseStatusMap) func(server.ReqHandler) server.ReqHandler {
	return func(handler server.ReqHandler) server.ReqHandler {
		return func(ctx server.ReqCtx) {
			ctx.SetUserValue("error_response", m)
			handler(ctx)
		}
	}
}
