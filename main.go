package main

import (
	"os"

	"github.com/gin-gonic/gin"
	routes "github.com/sahilkarwasra/GoLangJwtAuth/routes"
)

func main() {
	port := os.Getenv("PORT")

	if port == "" {
		port = "8000"
	}

	router := gin.New()

	router.Use(gin.Logger())

	routes.AuthRoutes(router)
	routes.UserRoutes(router)

	router.GET("/health-1", func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{"success": "Api 1 is working properly"})
	})

	router.GET("/health-2", func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{"success": "Api 2 is working properly"})
	})

	router.Run(":", port)
}
