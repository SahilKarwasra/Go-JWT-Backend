package utils

import "github.com/gin-gonic/gin"

type APIRespones struct {
	StatusCode int         `json:"statusCode"`
	IsSuccess  bool        `json:"isSuccess"`
	Data       interface{} `json:"data,omitempty"`
	Message    string      `json:"message"`
}

func SuccessApiResponse(
	ctx *gin.Context,
	statusCode int,
	data interface{},
	message string,
) {
	ctx.JSON(statusCode, APIRespones{
		StatusCode: statusCode,
		IsSuccess:  true,
		Data:       data,
		Message:    message,
	})
}

func ErrorApiResponse(
	ctx *gin.Context,
	statusCode int,
	message string,
) {
	ctx.JSON(statusCode, APIRespones{
		StatusCode: statusCode,
		IsSuccess:  false,
		Data:       nil,
		Message:    message,
	})
}
