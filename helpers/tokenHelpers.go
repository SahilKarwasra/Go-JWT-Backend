package helpers

import (
	"context"
	"fmt"
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

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "users")

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
			ID:        primitive.NewObjectID().Hex(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
		},
	}

	refreshClaims := &SignedDetails{
		Uid: userId,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        primitive.NewObjectID().Hex(),
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

	if err != nil {
		return err
	}

	return err
}

func VaildateAccessToken(signedToken string) (*SignedDetails, error) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&SignedDetails{},
		func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return []byte(SECRET_KEY), nil
		},
	)
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*SignedDetails)
	if !ok {
		return nil, fmt.Errorf("invalid claim type")
	}

	return claims, nil

}
