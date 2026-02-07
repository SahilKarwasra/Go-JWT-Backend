package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sahilkarwasra/GoLangJwtAuth/helpers"
)

func Authenticate() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		clientAccessToken := ctx.Request.Header.Get("accessToken")
		if clientAccessToken == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "access token not provided"})
			ctx.Abort()
			return
		}

		claims, err := helpers.VaildateAccessToken(clientAccessToken)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err})
			ctx.Abort()
			return
		}
		ctx.Set("email", claims.Email)
		ctx.Set("first_name", claims.First_name)
		ctx.Set("last_name", claims.Last_name)
		ctx.Set("uid", claims.Uid)
		ctx.Set("user_type", claims.User_type)
		ctx.Next()
	}
}
