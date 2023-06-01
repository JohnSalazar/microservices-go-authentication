package repositories

import (
	"fmt"

	"github.com/oceano-dev/microservices-go-common/config"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func NewMongoClient(config *config.Config) (*mongo.Client, error) {
	var login string
	if len(string(config.MongoDB.User)) > 0 && len(string(config.MongoDB.Password)) > 0 {
		login = fmt.Sprintf("%s:%s@", config.MongoDB.User, config.MongoDB.Password)
	}
	uri := fmt.Sprintf("mongodb://%s%s:%s/?maxPoolSize=%d&w=majority",
		login,
		config.MongoDB.Host,
		config.MongoDB.Port,
		config.MongoDB.MaxPoolSize)

	fmt.Println(uri)

	return mongo.NewClient(options.Client().ApplyURI(uri))
}

func NewMongoDatabase(
	config *config.Config,
	client *mongo.Client,
) *mongo.Database {
	return client.Database(config.MongoDB.Database)
}
