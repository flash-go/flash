package middleware

import (
	"github.com/flash-go/flash/http/server"
)

func Response(success server.SuccessResponse, err server.ErrorResponse) func(server.ReqHandler) server.ReqHandler {
	return func(handler server.ReqHandler) server.ReqHandler {
		return func(ctx server.ReqCtx) {
			ctx.SetUserValue(
				"response",
				server.ResponseConfig{
					Success: success,
					Err:     err,
				},
			)
			handler(ctx)
		}
	}
}
