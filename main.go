package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	routes "github.com/sahilkarwasra/GoLangJwtAuth/routes"
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("error loading .env file")
	}
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

	router.Run(":" + port)
}
