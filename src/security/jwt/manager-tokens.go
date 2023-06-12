package security

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"authentication/src/models"
	"authentication/src/security"

	"github.com/JohnSalazar/microservices-go-common/config"
	common_models "github.com/JohnSalazar/microservices-go-common/models"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

type ManagerToken struct {
	config              *config.Config
	managerSecurityKeys security.ManagerSecurityKeys
}

func NewManagerToken(
	config *config.Config,
	managerSecurityKeys security.ManagerSecurityKeys,
) *ManagerToken {
	return &ManagerToken{
		config:              config,
		managerSecurityKeys: managerSecurityKeys,
	}
}

func (m *ManagerToken) CreateAccessToken(c *gin.Context, user *models.User) (string, error) {
	if user.ID.IsZero() {
		return "", errors.New("user id is required")
	}

	if user.Email == "" {
		return "", errors.New("user email is required")
	}

	modelPrivateKey := m.managerSecurityKeys.GetNewestPrivateKey()
	if modelPrivateKey == nil {
		return "", errors.New("error retrieving privateKey")
	}

	tokenID := uuid.New().String()
	// issuer := fmt.Sprintf("%s://%s", location.Get(c).Scheme, c.Request.Host)
	issuer := m.config.Token.Issuer
	timeToken := time.Now().UTC()
	timeExpiration := timeToken.Add(time.Minute * time.Duration(m.config.Token.MinutesToExpireToken))
	tokenClaims := &common_models.TokenClaims{
		Sub:    user.ID.Hex(),
		Email:  user.Email,
		Jti:    tokenID,
		Nbf:    timeToken.Unix(),
		Iat:    timeToken.Unix(),
		Exp:    timeExpiration.Unix(),
		Iss:    issuer,
		Claims: []common_models.Claims(user.Claims),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   user.ID.Hex(),
			ExpiresAt: jwt.NewNumericDate(timeExpiration),
			NotBefore: jwt.NewNumericDate(timeToken),
			IssuedAt:  jwt.NewNumericDate(timeToken),
			ID:        tokenID,
		},
	}

	tokenClaimsToJson, err := json.Marshal(tokenClaims)
	if err != nil {
		return "", err
	}

	var jwtClaims jwt.MapClaims
	err = json.Unmarshal(tokenClaimsToJson, &jwtClaims)
	if err != nil {
		return "", nil
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwtClaims)

	var mux sync.Mutex
	mux.Lock()
	token.Header["kid"] = modelPrivateKey.Kid
	token.Header["typ"] = "access"
	mux.Unlock()

	tokenString, err := token.SignedString(modelPrivateKey.PrivateKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (m *ManagerToken) CreateRefreshToken(c *gin.Context, ID primitive.ObjectID) (string, error) {
	if ID.IsZero() {
		return "", errors.New("user id is required")
	}

	modelPrivateKey := m.managerSecurityKeys.GetNewestPrivateKey()
	if modelPrivateKey == nil {
		return "", errors.New("error retrieving privateKey")
	}

	issuer := m.config.Token.Issuer
	timeToken := time.Now().UTC()
	timeExpiration := timeToken.Add(time.Hour * time.Duration(m.config.Token.HoursToExpireRefreshToken))
	tokenClaims := &common_models.TokenClaims{
		Sub: ID.Hex(),
		Exp: timeExpiration.Unix(),
		Iss: issuer,
	}

	tokenClaimsToJson, err := json.Marshal(tokenClaims)
	if err != nil {
		return "", err
	}

	var jwtClaims jwt.MapClaims
	err = json.Unmarshal(tokenClaimsToJson, &jwtClaims)
	if err != nil {
		return "", nil
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwtClaims)

	var mux sync.Mutex
	mux.Lock()
	token.Header["kid"] = modelPrivateKey.Kid
	token.Header["typ"] = "refresh"
	mux.Unlock()

	refreshTokenString, err := token.SignedString(modelPrivateKey.PrivateKey)
	if err != nil {
		return "", err
	}

	return refreshTokenString, nil
}

// func (m *ManagerToken) SetAccessTokenToHead(c *gin.Context, token string) {
// 	c.Writer.Header().Set("Authorization", "Bearer "+token)
// }

// func (m *ManagerToken) RemoveHeadAccessToken(c *gin.Context) {
// 	c.Request.Header.Del("Authorization")
// }

// func (m *ManagerToken) SetAccessTokenToCookie(c *gin.Context, token string) {
// 	maxAge := 60 * m.config.Token.MinutesToExpireToken
// 	c.SetCookie("accessToken", token, maxAge, "/", "", false, false)
// 	// c.SetCookie("accessToken", token, maxAge, "/", "", false, true)
// }

// func (m *ManagerToken) RemoveCookieAccessToken(c *gin.Context) {
// 	c.SetCookie("accessToken", "", 0, "/", "", false, true)
// }
