package helpers

import (
	"context"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sahilkarwasra/GoLangJwtAuth/database"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type SignedDetails struct {
	Email      string
	First_name string
	Last_name  string
	Uid        string
	User_type  string
	jwt.RegisteredClaims
}

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")

var SECRET_KEY string = os.Getenv("SECRET_KEY")

func GenerateAllToken(email string, firstName string, lastName string, userType string, userId string) (signedAccessToken string, signedRefreshToken string, err error) {
	now := time.Now()
	accessClaims := &SignedDetails{
		Email:      email,
		First_name: firstName,
		Last_name:  lastName,
		Uid:        userId,
		User_type:  userType,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
		},
	}

	refreshClaims := &SignedDetails{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(7 * 24 * time.Hour)),
		},
	}

	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims).SignedString([]byte(SECRET_KEY))
	if err != nil {
		return "", "", err
	}
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString([]byte(SECRET_KEY))
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func UpdateAllToken(ctx context.Context, signedAccessToken string, signedRefreshToken string, userId string) error {
	ctxTimeout, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	var updateObj primitive.D

	updateObj = bson.D{
		{Key: "access_token", Value: signedAccessToken},
		{Key: "refresh_token", Value: signedRefreshToken},
		{Key: "updated_at", Value: time.Now()},
	}

	filter := bson.M{"user_id": userId}

	update := bson.D{
		{Key: "$set", Value: updateObj},
	}

	_, err := userCollection.UpdateOne(
		ctxTimeout,
		filter,
		update,
	)

	return err
}
