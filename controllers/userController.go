package controllers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/sahilkarwasra/GoLangJwtAuth/database"
	"github.com/sahilkarwasra/GoLangJwtAuth/helpers"
	"github.com/sahilkarwasra/GoLangJwtAuth/models"
	"github.com/sahilkarwasra/GoLangJwtAuth/utils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "users")
var validate = validator.New()

func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func VerifyPassword(providedPassword string, hashedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(providedPassword))

	return err == nil
}

func SignUp() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var ctxTimeout, cancel = context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		var user models.User

		if err := ctx.ShouldBindJSON(&user); err != nil {
			utils.ErrorApiResponse(ctx, http.StatusBadRequest, err.Error())
			return
		}

		if err := validate.Struct(user); err != nil {
			utils.ErrorApiResponse(ctx, http.StatusBadRequest, err.Error())
			return
		}

		emailCount, err := userCollection.CountDocuments(ctxTimeout, bson.M{"email": user.Email})
		if err != nil {
			utils.ErrorApiResponse(ctx, http.StatusInternalServerError, "error checking email")
			return
		}
		if emailCount > 0 {
			utils.ErrorApiResponse(ctx, http.StatusConflict, "this email already exists")
			return
		}

		hashedPassword, err := HashPassword(*user.Password)
		if err != nil {
			utils.ErrorApiResponse(ctx, http.StatusInternalServerError, "failed to hash password")
			return
		}
		user.Password = &hashedPassword

		phoneCount, err := userCollection.CountDocuments(ctxTimeout, bson.M{"phone": user.Phone})
		if err != nil {
			// ctx.JSON(http.StatusInternalServerError, gin.H{"error": "error checking phone"})
			utils.ErrorApiResponse(ctx, http.StatusInternalServerError, "error checking phone")
			return
		}
		if phoneCount > 0 {
			// ctx.JSON(http.StatusConflict, gin.H{"error": "this phone number already exists"})
			utils.ErrorApiResponse(ctx, http.StatusConflict, "this phone number already exists")
			return
		}

		now := time.Now()
		user.Created_at = now
		user.Updated_at = now
		user.ID = primitive.NewObjectID()
		user.User_id = user.ID.Hex()
		accessToken, refreshToken, err := helpers.GenerateAllToken(*user.Email, *user.First_name, *user.Last_name, *user.User_type, user.User_id)
		if err != nil {
			// ctx.JSON(http.StatusInternalServerError, gin.H{"error": "token generation failed"})
			utils.ErrorApiResponse(ctx, http.StatusInternalServerError, "token generation failed")
			return
		}

		user.Access_token = &accessToken
		user.Refresh_token = &refreshToken

		_, insertErr := userCollection.InsertOne(ctxTimeout, user)
		if insertErr != nil {
			msg := "user was not created"
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}

		// ctx.JSON(http.StatusCreated, gin.H{
		// 	"message": "User Registered Successfully",
		// 	"user_id": user.User_id,
		// })
		utils.SuccessApiResponse(ctx, http.StatusCreated, gin.H{
			"user_id": user.User_id,
		}, "user registered successfully")
	}
}

func Login() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var ctxTimeout, cancel = context.WithTimeout(ctx.Request.Context(), 60*time.Second)
		defer cancel()

		var user models.User
		var foundUser models.User

		// parse request body and store body in user
		if err := ctx.BindJSON(&user); err != nil {
			utils.ErrorApiResponse(ctx, http.StatusBadRequest, "invalid request body")
			return
		}

		// finding the user in db by email
		err := userCollection.FindOne(ctxTimeout, bson.M{"email": user.Email}).Decode(&foundUser)
		if err != nil {
			utils.ErrorApiResponse(ctx, http.StatusUnauthorized, "invalid credentials")
			return
		}

		if !VerifyPassword(*user.Password, *foundUser.Password) {
			utils.ErrorApiResponse(ctx, http.StatusUnauthorized, "invalid credentials")
			return
		}

		accessToken, refreshToken, err := helpers.GenerateAllToken(*foundUser.Email, *foundUser.First_name, *foundUser.Last_name, *foundUser.User_type, foundUser.User_id)
		if err != nil {
			utils.ErrorApiResponse(ctx, http.StatusInternalServerError, "could not generate access_token or refresh_token")
			return
		}

		err = helpers.UpdateAllToken(ctxTimeout, accessToken, refreshToken, foundUser.User_id)
		if err != nil {
			utils.ErrorApiResponse(ctx, http.StatusInternalServerError, "failed to update tokens")
			return
		}

		utils.SuccessApiResponse(ctx, http.StatusOK, gin.H{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
			"user_id":       foundUser.User_id,
		}, "logged in successfully")

	}
}

func RefreshToken() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var ctxTimeout, cancel = context.WithTimeout(ctx.Request.Context(), 60*time.Second)
		defer cancel()

		var req models.RefreshRequest

		// parse the user refresh token
		if err := ctx.ShouldBindJSON(&req); err != nil {
			utils.ErrorApiResponse(ctx, http.StatusBadRequest, "refresh token required")
			return
		}

		// validdate token signature and expire
		claims, err := helpers.VaildateAccessToken(req.RefreshToken)
		if err != nil {
			utils.ErrorApiResponse(ctx, http.StatusUnauthorized, "invalid refresh token")
			return
		}

		// fetch user from db
		var user models.User
		err = userCollection.FindOne(ctxTimeout, bson.M{"user_id": claims.Uid}).Decode(&user)
		if err != nil {
			utils.ErrorApiResponse(ctx, http.StatusUnauthorized, "user not found")
			return
		}

		// compare refresh token with db
		if user.Refresh_token == nil || *user.Refresh_token != req.RefreshToken {
			utils.ErrorApiResponse(ctx, http.StatusUnauthorized, "refresh token expired")
			return
		}

		// generate new token
		accessToken, refreshToken, err := helpers.GenerateAllToken(
			*user.Email,
			*user.First_name,
			*user.Last_name,
			*user.User_type,
			user.User_id,
		)
		if err != nil {
			utils.ErrorApiResponse(ctx, http.StatusInternalServerError, "failed to generate new tokens")
			return
		}

		// update token in db
		err = helpers.UpdateAllToken(ctx, accessToken, refreshToken, user.User_id)
		if err != nil {
			utils.ErrorApiResponse(ctx, http.StatusInternalServerError, "failed to update token")
		}

		// success response
		utils.SuccessApiResponse(
			ctx,
			http.StatusOK,
			gin.H{
				"access_token":  accessToken,
				"refresh_token": refreshToken,
			},
			"token refreshed successfully",
		)

	}
}

func GetUser() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		userId := ctx.Param("user_id")

		if err := helpers.MatchUserTypeToUid(ctx, userId); err != nil {
			// ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			utils.ErrorApiResponse(ctx, http.StatusBadRequest, "invalid user type")
			return
		}

		var ctxTimeout, cancel = context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		var user models.User
		err := userCollection.FindOne(ctxTimeout, bson.M{"user_id": userId}).Decode(&user)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				// ctx.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
				utils.ErrorApiResponse(ctx, http.StatusNotFound, "user not found")
			}
			// ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			utils.ErrorApiResponse(ctx, http.StatusInternalServerError, err.Error())
			return
		}
		// ctx.JSON(http.StatusOK, user)
		utils.SuccessApiResponse(ctx, http.StatusOK, user, "user fetched successfully")

	}
}
