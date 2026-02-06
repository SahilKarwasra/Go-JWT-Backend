package database

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func DBinstance() *mongo.Client {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error Loading .env File")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	MongoDb := os.Getenv("MONGO_URL")
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(MongoDb))
	if err != nil {
		log.Fatal(err)
	}

	// check connection if made or not
	if err := client.Ping(ctx, nil); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Connected to MongoDB Successfully!!")

	// return the client
	return client

}

var Client *mongo.Client = DBinstance()

func OpenCollection(client *mongo.Client, collectionName string) *mongo.Collection {
	var collection *mongo.Collection = client.Database("cluster0").Collection(collectionName)
	return collection
}
