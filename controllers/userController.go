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
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}

		// finding the user in db by email
		err := userCollection.FindOne(ctxTimeout, bson.M{"email": user.Email}).Decode(&foundUser)
		if err != nil {
			// ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			utils.ErrorApiResponse(ctx, http.StatusUnauthorized, "invalid credentials")
			return
		}

		if !VerifyPassword(*user.Password, *foundUser.Password) {
			// ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			utils.ErrorApiResponse(ctx, http.StatusUnauthorized, "invalid credentials")
			return
		}

		accessToken, refreshToken, err := helpers.GenerateAllToken(*foundUser.Email, *foundUser.First_name, *foundUser.Last_name, *foundUser.User_type, foundUser.User_id)
		if err != nil {
			// ctx.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate access_token and refresh_token"})
			utils.ErrorApiResponse(ctx, http.StatusInternalServerError, "could not generate access_token or refresh_token")
			return
		}

		err = helpers.UpdateAllToken(ctxTimeout, accessToken, refreshToken, foundUser.User_id)
		if err != nil {
			// ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update tokens"})
			utils.ErrorApiResponse(ctx, http.StatusInternalServerError, "failed to update tokens")
			return
		}

		// ctx.JSON(http.StatusOK, foundUser)
		utils.SuccessApiResponse(ctx, http.StatusOK, gin.H{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
			"user_id":       foundUser.User_id,
		}, "logged in successfully")

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
