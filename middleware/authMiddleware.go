package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sahilkarwasra/GoLangJwtAuth/database"
	"github.com/sahilkarwasra/GoLangJwtAuth/helpers"
	"github.com/sahilkarwasra/GoLangJwtAuth/models"
	"github.com/sahilkarwasra/GoLangJwtAuth/utils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "users")

func Authenticate() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		authHeader := ctx.GetHeader("Authorization")

		if authHeader == "" {
			utils.ErrorApiResponse(ctx, http.StatusUnauthorized, "authorization header missing")
			ctx.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			utils.ErrorApiResponse(ctx, http.StatusUnauthorized, "invalid authorization format")
			ctx.Abort()
			return
		}

		clientAccessToken := parts[1]

		if clientAccessToken == "" {
			utils.ErrorApiResponse(ctx, http.StatusUnauthorized, "access token not provided")
			ctx.Abort()
			return
		}

		claims, err := helpers.VaildateAccessToken(clientAccessToken)
		if err != nil {
			utils.ErrorApiResponse(ctx, http.StatusInternalServerError, "invalid access token")
			ctx.Abort()
			return
		}

		var user models.User
		err = userCollection.FindOne(ctx, bson.M{"user_id": claims.Uid}).Decode(&user)
		if err != nil {
			utils.ErrorApiResponse(ctx, http.StatusUnauthorized, "user not found")
			ctx.Abort()
			return
		}

		if user.Access_token == nil || *user.Access_token != clientAccessToken {
			utils.ErrorApiResponse(ctx, http.StatusUnauthorized, "session expired. please login again.")
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
