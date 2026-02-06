package helpers

import (
	"errors"

	"github.com/gin-gonic/gin"
)

func MatchUserTypeToUid(ctx *gin.Context, userId string) error {
	userType := ctx.GetString("user_type")
	uid := ctx.GetString("uid")

	// if normal user and trying to access someone else throw error
	if userType == "USER" {
		if uid != userId {
			return errors.New("Unauthorised access to this resource")
		}
		return nil
	}

	// if user is admin he can access everything
	if userType == "ADMIN" {
		return nil
	}

	return errors.New("Unauthrised access to this resource")

}
