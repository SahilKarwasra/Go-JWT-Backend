package routes

import (
	"github.com/gin-gonic/gin"
	controllers "github.com/sahilkarwasra/GoLangJwtAuth/controllers"
	"github.com/sahilkarwasra/GoLangJwtAuth/middleware"
)

func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.Use(middleware.Authenticate())
	incomingRoutes.GET("/users", controllers.GetUsers())
	incomingRoutes.GET("/users/:user_id", controllers.GetUser())
}
