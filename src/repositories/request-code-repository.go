package repositories

import (
	"context"
	"time"

	"github.com/oceano-dev/microservices-go-common/helpers"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type requestCodeRepository struct {
	database *mongo.Database
}

func NewRequestCodeRepository(
	database *mongo.Database,
) *requestCodeRepository {
	return &requestCodeRepository{
		database: database,
	}
}

func (r *requestCodeRepository) collectionName() string {
	return "requestCodes"
}

func (r *requestCodeRepository) collection() *mongo.Collection {
	return r.database.Collection(r.collectionName())
}

func (r *requestCodeRepository) findOneAndUpdate(ctx context.Context, filter interface{}, fields interface{}) bool {
	findOneAndUpdateOptions := options.FindOneAndUpdateOptions{}
	findOneAndUpdateOptions.SetReturnDocument(options.After)
	findOneAndUpdateOptions.SetSort(bson.M{"expires_at": -1})

	newFilter := map[string]interface{}{
		"expires_at": bson.M{"$gte": time.Now().UTC()},
	}
	mergeFilter := helpers.MergeFilters(newFilter, filter)

	result := r.collection().FindOneAndUpdate(ctx, mergeFilter, fields, &findOneAndUpdateOptions)

	return result.Err() == nil
}

func (r *requestCodeRepository) CodeExists(ctx context.Context, email string, code string) bool {
	filter := map[string]interface{}{
		"email": email, "code": code,
	}

	result := r.collection().FindOne(ctx, filter)

	return result.Err() == nil
}

func (r *requestCodeRepository) CreateCode(ctx context.Context, email string, code string) error {
	fields := bson.M{
		"_id":        primitive.NewObjectID(),
		"email":      email,
		"code":       code,
		"expires_at": time.Now().UTC().Add(5 * time.Minute),
	}

	_, err := r.collection().InsertOne(ctx, fields)

	return err
}

func (r *requestCodeRepository) ValidatePasswordUpdateCode(ctx context.Context, email string, code string) bool {
	filter := bson.M{"email": email, "code": code}

	fields := bson.M{"expires_at": time.Now().UTC()}

	return r.findOneAndUpdate(ctx, filter, bson.M{"$set": fields})
}
