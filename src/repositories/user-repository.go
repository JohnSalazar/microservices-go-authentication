package repositories

import (
	"context"
	"strings"
	"time"

	"authentication/src/models"

	helpers "github.com/oceano-dev/microservices-go-common/helpers"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type userRepository struct {
	database *mongo.Database
}

func NewUserRepository(
	database *mongo.Database,
) *userRepository {
	return &userRepository{
		database: database,
	}
}

func (r *userRepository) collectionName() string {
	return "users"
}

func (r *userRepository) collection() *mongo.Collection {
	return r.database.Collection(r.collectionName())
}

func (r *userRepository) find(ctx context.Context, filter interface{}, page int, size int) ([]*models.User, error) {
	findOptions := options.FindOptions{}
	findOptions.SetSort(bson.M{"email": 1})

	page64 := int64(page)
	size64 := int64(size)
	findOptions.SetSkip((page64 - 1) * size64)
	findOptions.SetLimit(size64)

	newFilter := map[string]interface{}{
		"deleted": false,
	}
	mergeFilter := helpers.MergeFilters(newFilter, filter)

	cursor, err := r.collection().Find(ctx, mergeFilter, &findOptions)
	if err != nil {
		defer cursor.Close(ctx)
		return nil, err
	}

	var users []*models.User

	for cursor.Next(ctx) {
		user := &models.User{}

		err = cursor.Decode(user)
		if err != nil {
			return nil, err
		}

		users = append(users, user)
	}

	return users, nil
}

func (r *userRepository) findOne(ctx context.Context, filter interface{}) (*models.User, error) {
	findOneOptions := options.FindOneOptions{}
	findOneOptions.SetSort(bson.M{"version": -1})

	newFilter := map[string]interface{}{
		"deleted": false,
	}
	mergeFilter := helpers.MergeFilters(newFilter, filter)

	user := &models.User{}
	err := r.collection().FindOne(ctx, mergeFilter, &findOneOptions).Decode(user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (r *userRepository) GetUsersWithClaim(ctx context.Context, email string, page int, size int) ([]*models.User, error) {
	// filter := bson.M{"email": bson.M{"$regex": primitive.Regex{Pattern: email, Options: "i"}}, "claims": bson.M{"$exists": true}}

	var filter map[string]interface{}
	if len(strings.TrimSpace(email)) > 0 {
		filter = bson.M{"email": bson.M{"$regex": primitive.Regex{Pattern: email, Options: "i"}}}
	} else {
		filter = bson.M{"claims": bson.M{"$exists": true, "$ne": nil}}
	}

	return r.find(ctx, filter, page, size)
}

func (r *userRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	filter := bson.M{"email": email}

	return r.findOne(ctx, filter)
}

func (r *userRepository) FindByID(ctx context.Context, ID primitive.ObjectID) (*models.User, error) {
	filter := bson.M{"_id": ID}

	return r.findOne(ctx, filter)
}

func (r *userRepository) Create(ctx context.Context, user *models.User) error {
	fields := bson.M{
		"_id":        user.ID,
		"email":      user.Email,
		"password":   user.Password,
		"claims":     user.Claims,
		"created_at": time.Now().UTC(),
		"version":    0,
		"deleted":    false,
	}

	_, err := r.collection().InsertOne(ctx, fields)

	return err
}

func (r *userRepository) findOneAndUpdate(ctx context.Context, filter interface{}, fields interface{}) *mongo.SingleResult {
	findOneAndUpdateOptions := options.FindOneAndUpdateOptions{}
	findOneAndUpdateOptions.SetReturnDocument(options.After)

	result := r.collection().FindOneAndUpdate(ctx, filter, bson.M{"$set": fields}, &findOneAndUpdateOptions)

	return result
}

func (r *userRepository) UpdateEmail(ctx context.Context, user *models.User) (*models.User, error) {
	// user.Version++
	fields := bson.M{
		"email":      user.Email,
		"updated_at": time.Now().UTC(),
		"version":    user.Version + 1,
	}

	filter := r.filterUpdate(user)

	result := r.findOneAndUpdate(ctx, filter, fields)
	if result.Err() != nil {
		return nil, result.Err()
	}

	modelUser := &models.User{}
	decodeErr := result.Decode(modelUser)

	return modelUser, decodeErr
}

func (r *userRepository) UpdatePassword(ctx context.Context, user *models.User) (*models.User, error) {
	// user.Version++
	fields := bson.M{
		"password":   user.Password,
		"updated_at": time.Now().UTC(),
		"version":    user.Version + 1,
	}

	filter := r.filterUpdate(user)

	result := r.findOneAndUpdate(ctx, filter, fields)
	if result.Err() != nil {
		return nil, result.Err()
	}

	modelUser := &models.User{}
	decodeErr := result.Decode(modelUser)

	return modelUser, decodeErr
}

func (r *userRepository) UpdateClaims(ctx context.Context, user *models.User) (*models.User, error) {
	// user.Version++
	fields := bson.M{
		"claims":     user.Claims,
		"updated_at": time.Now().UTC(),
		"version":    user.Version + 1,
	}

	filter := r.filterUpdate(user)

	result := r.findOneAndUpdate(ctx, filter, fields)
	if result.Err() != nil {
		return nil, result.Err()
	}

	modelUser := &models.User{}
	decodeErr := result.Decode(modelUser)

	return modelUser, decodeErr
}

func (r *userRepository) Delete(ctx context.Context, ID primitive.ObjectID) error {
	filter := bson.M{"_id": ID}

	fields := bson.M{"deleted": true}

	result := r.findOneAndUpdate(ctx, filter, fields)
	if result.Err() != nil {
		return result.Err()
	}

	return nil
}

func (r *userRepository) filterUpdate(user *models.User) interface{} {
	filter := bson.M{
		"_id":     user.ID,
		"version": user.Version,
	}

	return filter
}
