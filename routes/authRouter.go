package routes

import (
	"github.com/gin-gonic/gin"
	controllers "github.com/sahilkarwasra/GoLangJwtAuth/controllers"
)

func AuthRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.POST("/login", controllers.Login())
	incomingRoutes.POST("/signUp", controllers.SignUp())
}
