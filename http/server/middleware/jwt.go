package middleware

import (
	"errors"
	"strings"

	"github.com/flash-go/flash/http/server"
	"github.com/golang-jwt/jwt"
)

type JwtConfig struct {
	Key            []byte
	SuccessHandler server.ReqHandler
	ErrorHandler   func(ctx server.ReqCtx, err error)
}

func NewJwt(config JwtConfig) server.ReqHandler {
	return func(ctx server.ReqCtx) {
		authHeader := string(ctx.Request().Header.Peek("Authorization"))

		if authHeader == "" {
			config.ErrorHandler(ctx, errors.New("authorization header not found"))
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			config.ErrorHandler(ctx, errors.New("missing Bearer token"))
			return
		}

		tokenString := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer"))

		t, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return config.Key, nil
		})
		if err != nil {
			config.ErrorHandler(ctx, err)
			return
		}

		if claims, ok := t.Claims.(jwt.MapClaims); ok && t.Valid {
			ctx.SetUserValue("user", claims["id"])
			ctx.SetUserValue("role", claims["role"])
			ctx.SetUserValue("otp", claims["otp"])
		}

		config.SuccessHandler(ctx)
	}
}
