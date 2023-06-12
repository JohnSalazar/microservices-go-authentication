package repositories

import (
	"context"
	"time"

	"authentication/src/models"

	trace "github.com/JohnSalazar/microservices-go-common/trace/otel"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type securityKeysRepository struct {
	database *mongo.Database
}

func NewSecurityKeysRepository(
	database *mongo.Database,
) *securityKeysRepository {
	return &securityKeysRepository{
		database: database,
	}
}

func (r *securityKeysRepository) collectionName() string {
	return "securityKeys"
}

func (r *securityKeysRepository) collection() *mongo.Collection {
	return r.database.Collection(r.collectionName())
}

func (r *securityKeysRepository) GetPrivateKeysParams(ctx context.Context) ([]*models.ECDSAPrivateKeysParams, error) {
	ctx, span := trace.NewSpan(ctx, "securityKeysRepository.getPrivateKeysParams")
	defer span.End()

	findOptions := options.FindOptions{}
	findOptions.SetSort(bson.M{"expires_at": -1})

	filter := bson.M{"expires_at": bson.M{"$gte": time.Now().UTC()}}

	// fmt.Println("r.database: ", r.database.Name())

	cursor, err := r.collection().Find(ctx, filter, &findOptions)
	if err != nil {
		defer cursor.Close(ctx)
		return nil, err
	}

	var params []*models.ECDSAPrivateKeysParams

	for cursor.Next(ctx) {
		param := &models.ECDSAPrivateKeysParams{}
		cursor.Decode(param)
		params = append(params, param)
	}

	return params, nil
}

func (r *securityKeysRepository) CreatePrivateKeysParams(ctx context.Context, securityKeysParams *models.ECDSAPrivateKeysParams) error {
	_, err := r.collection().InsertOne(ctx, securityKeysParams)

	return err
}

func (r *securityKeysRepository) DeletePrivateKeysParams(ctx context.Context) error {
	filter := bson.M{"expires_at": bson.M{"$lt": time.Now().UTC()}}

	_, err := r.collection().DeleteMany(ctx, filter)

	return err
}
