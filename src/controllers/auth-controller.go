package controllers

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/mail"
	"os"
	"strconv"

	"authentication/src/dtos"
	natsMetrics "authentication/src/nats/interfaces"

	"github.com/oceano-dev/microservices-go-common/httputil"
	trace "github.com/oceano-dev/microservices-go-common/trace/otel"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/oceano-dev/microservices-go-common/config"
	common_nats "github.com/oceano-dev/microservices-go-common/nats"

	helpers "github.com/oceano-dev/microservices-go-common/helpers"
	common_models "github.com/oceano-dev/microservices-go-common/models"
	common_security "github.com/oceano-dev/microservices-go-common/security"
	common_services "github.com/oceano-dev/microservices-go-common/services"

	httpresponsecredentials "authentication/src/http"

	"authentication/src/models"
	"authentication/src/security"
	jwt "authentication/src/security/jwt"

	"authentication/src/services"
	"authentication/src/validators"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type AuthController struct {
	logger              *logrus.Logger
	srvAuth             *services.AuthenticationService
	srvRequestCode      *services.RequestCodeService
	managerToken        *jwt.ManagerToken
	managerTokensCommon *common_security.ManagerTokens
	managerSecurityKeys security.ManagerSecurityKeys
	config              *config.Config
	publisher           common_nats.Publisher
	natsMetrics         natsMetrics.NatsMetric
	certificateServices common_services.CertificatesService
}

func NewAuthController(
	logger *logrus.Logger,
	srvAuth *services.AuthenticationService,
	srvRequestCode *services.RequestCodeService,
	managerToken *jwt.ManagerToken,
	managerTokensCommon *common_security.ManagerTokens,
	managerSecurityKeys security.ManagerSecurityKeys,
	config *config.Config,
	publisher common_nats.Publisher,
	natsMetrics natsMetrics.NatsMetric,
	certificateServices common_services.CertificatesService,
) *AuthController {
	return &AuthController{
		logger:              logger,
		srvAuth:             srvAuth,
		srvRequestCode:      srvRequestCode,
		managerToken:        managerToken,
		managerTokensCommon: managerTokensCommon,
		managerSecurityKeys: managerSecurityKeys,
		config:              config,
		publisher:           publisher,
		natsMetrics:         natsMetrics,
		certificateServices: certificateServices,
	}
}

// Signup godoc
// @Summary      Signup user
// @Description  add by json user
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        user  body      dtos.SignUp                true  "Add user and get credentials"
// @Success      201   {object}  httpresponsecredentials.ResponseCredentials
// @Failure      400   {object}  httputil.ResponseError
// @Failure      500   {object}  httputil.ResponseError
// @Router       /signup [post]
func (auth *AuthController) Signup(c *gin.Context) {
	signUpDTO := &dtos.SignUp{}
	err := c.BindJSON(signUpDTO)
	if err != nil {
		httputil.NewResponseError(c, http.StatusBadRequest, err.Error())
		return
	}

	if signUpDTO.PasswordConfirm == "" {
		httputil.NewResponseError(c, http.StatusBadRequest, "PasswordConfirm is a required field")
		return
	}

	result := validators.ValidateSignUP(signUpDTO)
	if result != nil {
		httputil.NewResponseError(c, http.StatusBadRequest, result)
		return
	}

	userExists, _ := auth.srvAuth.FindByEmail(c.Request.Context(), signUpDTO.Email)
	if userExists != nil {
		httputil.NewResponseError(c, http.StatusBadRequest, "user already exists")
		return
	}

	userMapped := &models.User{
		Email:    signUpDTO.Email,
		Password: signUpDTO.Password,
	}

	user, err := auth.srvAuth.Create(c.Request.Context(), userMapped)
	if err != nil {
		httputil.NewResponseError(c, http.StatusInternalServerError, err.Error())
		return
	}

	// accessToken, err := createTokenAndSetHead(c, auth.managerToken, user)
	accessToken, err := createAccessToken(c, auth.managerToken, user)
	if err != nil {
		httputil.NewResponseError(c, http.StatusInternalServerError, err.Error())
		return
	}

	refreshToken, err := createRefreshToken(c, auth.managerToken, user.ID)
	if err != nil {
		httputil.NewResponseError(c, http.StatusInternalServerError, err.Error())
		return
	}

	httpresponsecredentials.NewResponseCredentials(c, http.StatusCreated, user, accessToken, refreshToken)
}

// CreateUser godoc
// @Summary      Create user
// @Description  create by json user
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        user  body      dtos.CreateUser                true  "Create user"
// @Success      201   {object}  dtos.UserCredentials
// @Failure      400   {object}  httputil.ResponseError
// @Failure      403   {object}  httputil.ResponseError
// @Failure      500   {object}  httputil.ResponseError
// @Router       /user [post]
// @Security Bearer
func (auth *AuthController) CreateUser(c *gin.Context) {
	createUserDTO := &dtos.CreateUser{}
	err := c.BindJSON(createUserDTO)
	if err != nil {
		httputil.NewResponseError(c, http.StatusBadRequest, err.Error())
		return
	}

	result := validators.ValidateCreateUser(createUserDTO)
	if result != nil {
		httputil.NewResponseError(c, http.StatusBadRequest, result)
		return
	}

	userExists, _ := auth.srvAuth.FindByEmail(c.Request.Context(), createUserDTO.Email)
	if userExists != nil {
		httputil.NewResponseError(c, http.StatusBadRequest, "user already exists")
		return
	}

	userMapped := &models.User{
		Email:    createUserDTO.Email,
		Password: createUserDTO.Password,
		Claims:   createUserDTO.Claims,
	}

	user, err := auth.srvAuth.Create(c.Request.Context(), userMapped)
	if err != nil {
		httputil.NewResponseError(c, http.StatusInternalServerError, err.Error())
		return
	}

	httpresponsecredentials.NewResponseUser(c, http.StatusCreated, user)
}

// Signin godoc
// @Summary      Signin user
// @Description  get by json user token refreshToken
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        user  body      dtos.SignIn                true  "Get credentials"
// @Success      200   {object}  httpresponsecredentials.ResponseCredentials
// @Failure      400   {object}  httputil.ResponseError
// @Failure      500   {object}  httputil.ResponseError
// @Router       /signin [post]
func (auth *AuthController) Signin(c *gin.Context) {
	// log := auth.addLog("Login")

	signInDTO := &dtos.SignIn{}
	if err := c.BindJSON(signInDTO); err != nil {
		// log.WithField("err", err).Info("invalid JSON")
		httputil.NewResponseError(c, http.StatusBadRequest, err.Error())
		return
	}

	result := validators.ValidateSignIn(signInDTO)
	if result != nil {
		httputil.NewResponseError(c, http.StatusBadRequest, result)
		return
	}

	user, err := auth.srvAuth.FindByEmail(c.Request.Context(), signInDTO.Email)
	if err != nil {
		httputil.NewResponseError(c, http.StatusBadRequest, "email not found")
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(signInDTO.Password)); err != nil {
		httputil.NewResponseError(c, http.StatusBadRequest, "invalid credentials")
		return
	}

	// accessToken, err := createTokenAndSetHead(c, auth.managerToken, user)
	accessToken, err := createAccessToken(c, auth.managerToken, user)
	if err != nil {
		httputil.NewResponseError(c, http.StatusInternalServerError, err.Error())
		return
	}

	refreshToken, err := createRefreshToken(c, auth.managerToken, user.ID)
	if err != nil {
		httputil.NewResponseError(c, http.StatusInternalServerError, err.Error())
		return
	}

	httpresponsecredentials.NewResponseCredentials(c, http.StatusOK, user, accessToken, refreshToken)
}

// GetUsersWithClaim godoc
// @Summary      Get users with claim
// @Description  Get users with claim
// @Tags         users
// @Accept       json
// @Produce      json
// @Param				 email	path		string	false	"Email"
// @Param				 page 	path		int 		true	"Page"
// @Param				 size 	path		int 		true	"Size"
// @Success      200   {object}  []dtos.User
// @Failure      400   {object}  httputil.ResponseError
// @Failure      403   {object}  httputil.ResponseError
// @Failure      500   {object}  httputil.ResponseError
// @Router       /{email}/{page}/{size} [get]
// @Security Bearer
func (auth *AuthController) GetUsersWithClaim(c *gin.Context) {
	email := c.Param("email")

	page, err := strconv.Atoi(c.Param("page"))
	if err != nil {
		httputil.NewResponseError(c, http.StatusBadRequest, "page is required")
		return
	}

	size, err := strconv.Atoi(c.Param("size"))
	if err != nil {
		httputil.NewResponseError(c, http.StatusBadRequest, "size is required")
		return
	}
	users, err := auth.srvAuth.GetUsersWithClaim(c.Request.Context(), email, page, size)
	if err != nil {
		httputil.NewResponseError(c, http.StatusBadRequest, "users not found")
		return
	}

	var usersDTO []*dtos.User
	for _, user := range users {
		userDTO := mapToUserDTO(user)
		usersDTO = append(usersDTO, userDTO)
	}

	c.JSON(http.StatusOK, usersDTO)
}

// Profile godoc
// @Summary      Profile user
// @Description  get user info
// @Tags         users
// @Accept       json
// @Produce      json
// @Success      200  {object}  dtos.User
// @Failure      400  {object}  httputil.ResponseError
// @Failure      401  {object}  httputil.ResponseError
// @Router       /profile [get]
// @Security Bearer
func (auth *AuthController) Profile(c *gin.Context) {
	ID, userIDOk := c.Get("user")
	if !userIDOk {
		httputil.NewResponseError(c, http.StatusForbidden, "invalid Id")
		return
	}

	user, err := auth.srvAuth.FindByID(c.Request.Context(), helpers.StringToID(ID.(string)))
	if err != nil {
		httputil.NewResponseError(c, http.StatusBadRequest, "user not found")
		return
	}

	userDTO := mapToUserDTO(user)

	c.JSON(http.StatusOK, userDTO)
}

// UpdateEmail godoc
// @Summary      Update an user email
// @Description  update by json user email
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        id              path                  string                          true  "User ID"
// @Param        user  body      dtos.UpdateEmail                  true  "Update user email"
// @Success      200   {object}  httpresponsecredentials.ResponseCredentials
// @Failure      400   {object}  httputil.ResponseError
// @Failure      401   {object}  httputil.ResponseError
// @Failure      500   {object}  httputil.ResponseError
// @Router       /email/{id} [put]
// @Security Bearer
func (auth *AuthController) UpdateEmail(c *gin.Context) {
	isID := helpers.IsValidID(c.Param("id"))
	if !isID {
		httputil.NewResponseError(c, http.StatusBadRequest, "invalid Id")
		return
	}

	ID := helpers.StringToID(c.Param("id"))

	getUserID, userIDOk := c.Get("user")
	if !userIDOk {
		httputil.NewResponseError(c, http.StatusForbidden, "invalid customer")
		return
	}

	if ID != helpers.StringToID(getUserID.(string)) {
		httputil.NewResponseError(c, http.StatusForbidden, "you can only change your account")
		return
	}

	updateEmailDTO := &dtos.UpdateEmail{}
	err := c.BindJSON(updateEmailDTO)
	if err != nil {
		httputil.NewResponseError(c, http.StatusForbidden, err.Error())
		return
	}

	if !helpers.IsValidID(updateEmailDTO.ID) {
		httputil.NewResponseError(c, http.StatusBadRequest, "invalid Id")
		return
	}

	result := validators.ValidateUpdateEmail(updateEmailDTO)
	if result != nil {
		httputil.NewResponseError(c, http.StatusBadRequest, result)
		return
	}

	userExists, err := auth.srvAuth.FindByID(c.Request.Context(), ID)
	if err != nil {
		httputil.NewResponseError(c, http.StatusBadRequest, "user not found")
		return
	}

	if helpers.StringToID(updateEmailDTO.ID) != userExists.ID {
		httputil.NewResponseError(c, http.StatusBadRequest, "user not found")
		return
	}

	userMapped := &models.User{
		ID:      userExists.ID,
		Email:   updateEmailDTO.Email,
		Version: updateEmailDTO.Version,
	}

	user, err := auth.srvAuth.UpdateEmail(c.Request.Context(), userMapped)
	if err != nil {
		httputil.NewResponseError(c, http.StatusInternalServerError, err.Error())
		return
	}

	// accessToken, err := createTokenAndSetHead(c, auth.managerToken, user)
	accessToken, err := createAccessToken(c, auth.managerToken, user)
	if err != nil {
		httputil.NewResponseError(c, http.StatusInternalServerError, err.Error())
		return
	}

	refreshToken, err := createRefreshToken(c, auth.managerToken, user.ID)
	if err != nil {
		httputil.NewResponseError(c, http.StatusInternalServerError, err.Error())
		return
	}

	httpresponsecredentials.NewResponseCredentials(c, http.StatusOK, user, accessToken, refreshToken)
}

// RequestUpdatePassword godoc
// @Summary      Request a user password update
// @Description  update by json user password
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        user  body      dtos.RequestUpdatePassword  true  "Update user password"
// @Success      201   {object}  httpresponsecredentials.ResponseCredentials
// @Failure      400   {object}  httputil.ResponseError
// @Failure      500   {object}  httputil.ResponseError
// @Router       /request-update-password [post]
func (auth *AuthController) RequestUpdatePassword(c *gin.Context) {
	requestUpdatePasswordDTO := &dtos.RequestUpdatePassword{}
	err := c.BindJSON(requestUpdatePasswordDTO)
	if err != nil {
		httputil.NewResponseError(c, http.StatusBadRequest, err.Error())
		return
	}

	if requestUpdatePasswordDTO.Email == "" {
		httputil.NewResponseError(c, http.StatusBadRequest, "email is a required field")
		return
	}

	_, err = mail.ParseAddress(requestUpdatePasswordDTO.Email)
	if err != nil {
		httputil.NewResponseError(c, http.StatusBadRequest, "provide a valid email")
		return
	}

	userExists, _ := auth.srvAuth.FindByEmail(c.Request.Context(), requestUpdatePasswordDTO.Email)
	if userExists == nil {
		httputil.NewResponseError(c, http.StatusBadRequest, "user not found")
		return
	}

	err = auth.srvRequestCode.CreateCode(c.Request.Context(), requestUpdatePasswordDTO.Email)
	if err != nil {
		httputil.NewResponseError(c, http.StatusInternalServerError, err.Error())
		return
	}

	httputil.NewResponseSuccess(c, http.StatusCreated, "check your email")
}

// UpdatePassword godoc
// @Summary      Update an user password
// @Description  update by json user password
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        email  path          string                                       true  "User Email"
// @Param        user   body          dtos.UpdatePassword          true  "Update user password"
// @Success      200    {object}  httpresponsecredentials.ResponseCredentials
// @Failure      400  {object}  httputil.ResponseError
// @Failure      500  {object}  httputil.ResponseError
// @Router       /password/{email} [put]
func (auth *AuthController) UpdatePassword(c *gin.Context) {
	email := c.Param("email")
	_, err := mail.ParseAddress(email)
	if err != nil {
		httputil.NewResponseError(c, http.StatusBadRequest, "invalid email")
		return
	}

	updatePasswordDTO := &dtos.UpdatePassword{}
	err = c.BindJSON(updatePasswordDTO)
	if err != nil {
		httputil.NewResponseError(c, http.StatusForbidden, err.Error())
		return
	}

	if email != updatePasswordDTO.Email {
		httputil.NewResponseError(c, http.StatusBadRequest, "divergent email")
		return
	}

	if updatePasswordDTO.RequestUpdatePasswordCode == "" {
		httputil.NewResponseError(c, http.StatusBadRequest, "code not found")
		return
	}

	if updatePasswordDTO.PasswordConfirm == "" {
		httputil.NewResponseError(c, http.StatusBadRequest, "PasswordConfirm is a required field")
		return
	}

	result := validators.ValidateUpdatePassword(updatePasswordDTO)
	if result != nil {
		httputil.NewResponseError(c, http.StatusBadRequest, result)
		return
	}

	userExists, _ := auth.srvAuth.FindByEmail(c.Request.Context(), updatePasswordDTO.Email)
	if userExists == nil {
		httputil.NewResponseError(c, http.StatusBadRequest, "user not found")
		return
	}

	find := auth.srvRequestCode.ValidatePasswordUpdateCode(c, updatePasswordDTO.Email, updatePasswordDTO.RequestUpdatePasswordCode)
	if !find {
		httputil.NewResponseError(c, http.StatusBadRequest, "invalid code")
		return
	}

	userMapped := &models.User{
		ID:       userExists.ID,
		Password: updatePasswordDTO.Password,
		Version:  userExists.Version,
	}
	user, err := auth.srvAuth.UpdatePassword(c.Request.Context(), userMapped)
	if err != nil {
		httputil.NewResponseError(c, http.StatusInternalServerError, err.Error())
		return
	}

	// accessToken, err := createTokenAndSetHead(c, auth.managerToken, user)
	accessToken, err := createAccessToken(c, auth.managerToken, user)
	if err != nil {
		httputil.NewResponseError(c, http.StatusInternalServerError, err.Error())
		return
	}

	refreshToken, err := createRefreshToken(c, auth.managerToken, user.ID)
	if err != nil {
		httputil.NewResponseError(c, http.StatusInternalServerError, err.Error())
		return
	}

	httpresponsecredentials.NewResponseCredentials(c, http.StatusOK, user, accessToken, refreshToken)
}

// UpdateClaims godoc
// @Summary      Update an user claims
// @Description  update by json user claims
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        id    path      string                                       true  "User ID"
// @Param        user  body      dtos.UpdateClaims          true  "Update user claims"
// @Success      200   {object}  httpresponsecredentials.ResponseCredentials
// @Failure      400   {object}  httputil.ResponseError
// @Failure      401   {object}  httputil.ResponseError
// @Failure      403   {object}  httputil.ResponseError
// @Failure      500   {object}  httputil.ResponseError
// @Router       /claims/{id} [put]
// @Security Bearer
func (auth *AuthController) UpdateClaims(c *gin.Context) {
	isID := helpers.IsValidID(c.Param("id"))
	if !isID {
		httputil.NewResponseError(c, http.StatusBadRequest, "invalid Id")
		return
	}

	ID := helpers.StringToID(c.Param("id"))

	updateClaimsDTO := &dtos.UpdateClaims{}
	err := c.BindJSON(updateClaimsDTO)
	if err != nil {
		httputil.NewResponseError(c, http.StatusForbidden, err.Error())
		return
	}

	if !helpers.IsValidID(updateClaimsDTO.ID) {
		httputil.NewResponseError(c, http.StatusBadRequest, "invalid Id")
		return
	}

	userExists, err := auth.srvAuth.FindByID(c.Request.Context(), ID)
	if err != nil {
		httputil.NewResponseError(c, http.StatusBadRequest, "user not found")
		return
	}

	if helpers.StringToID(updateClaimsDTO.ID) != userExists.ID {
		httputil.NewResponseError(c, http.StatusBadRequest, "user not found")
		return
	}

	userMapped := &models.User{
		ID:      helpers.StringToID(updateClaimsDTO.ID),
		Claims:  []common_models.Claims(updateClaimsDTO.Claims),
		Version: updateClaimsDTO.Version,
	}

	user, err := auth.srvAuth.UpdateClaims(c.Request.Context(), userMapped)
	if err != nil {
		httputil.NewResponseError(c, http.StatusInternalServerError, err.Error())
		return
	}

	// accessToken, err := createTokenAndSetHead(c, auth.managerToken, user)
	accessToken, err := createAccessToken(c, auth.managerToken, user)
	if err != nil {
		httputil.NewResponseError(c, http.StatusInternalServerError, err.Error())
		return
	}

	refreshToken, err := createRefreshToken(c, auth.managerToken, user.ID)
	if err != nil {
		httputil.NewResponseError(c, http.StatusInternalServerError, err.Error())
		return
	}

	httpresponsecredentials.NewResponseCredentials(c, http.StatusOK, user, accessToken, refreshToken)
}

// DeleteUser godoc
// @Summary      Delete an user
// @Description  Delete by user ID
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        id   path      string                    true  "user ID"
// @Success      200  {object}  httpresponsecredentials.ResponseCredentials
// @Failure      400  {object}  httputil.ResponseError
// @Failure      401  {object}  httputil.ResponseError
// @Router       /{id} [delete]
// @Security Bearer
func (auth *AuthController) Delete(c *gin.Context) {
	ctx, span := trace.NewSpan(c.Request.Context(), "AuthController.Delete")
	defer span.End()

	ID := helpers.StringToID(c.Param("id"))

	getUserID, userIDOk := c.Get("user")
	if !userIDOk {
		httputil.NewResponseError(c, http.StatusForbidden, "invalid Id")
		return
	}

	if ID != helpers.StringToID(getUserID.(string)) {
		httputil.NewResponseError(c, http.StatusForbidden, "you can only delete your account")
		return
	}

	user, err := auth.srvAuth.FindByID(ctx, ID)
	if err != nil {
		httputil.NewResponseError(c, http.StatusBadRequest, "user not found")
		return
	}

	err = auth.srvAuth.Delete(c.Request.Context(), user.ID)
	if err != nil {
		httputil.NewResponseError(c, http.StatusBadRequest, err.Error())
		return
	}

	data, err := json.Marshal(user)
	if err != nil {
		trace.FailSpan(span, "Error json parse")
		log.Printf("Error json parse: %v", err)
	}

	err = auth.publisher.Publish(string(common_nats.UserDeleted), data)
	if err != nil {
		auth.natsMetrics.ErrorPublish()
		log.Printf("Error publisher: %v", err)
		// return
	}

	httputil.NewResponseSuccess(c, http.StatusOK, "deleted user")
}

// RefreshToken godoc
// @Summary      Request a user credentials
// @Description  request credentials by json refresh token
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        user  body      dtos.RefreshToken            true  "Refresh token user"
// @Success      200   {object}  httpresponsecredentials.ResponseCredentials
// @Failure      400   {object}  httputil.ResponseError
// @Failure      500   {object}  httputil.ResponseError
// @Router       /refresh-token [post]
func (auth *AuthController) RefreshToken(c *gin.Context) {
	// removeCookieAccessToken(c, auth.managerToken)

	msgErr := "invalid refresh token"

	refreshTokenDTO := &dtos.RefreshToken{}
	err := c.BindJSON(refreshTokenDTO)
	if err != nil {
		httputil.NewResponseError(c, http.StatusForbidden, err.Error())
		return
	}

	token := refreshTokenDTO.RefreshToken
	if token == "" {
		httputil.NewResponseError(c, http.StatusBadRequest, msgErr)
		return
	}

	id, err := auth.managerTokensCommon.ReadRefreshToken(c, token)
	if err != nil {
		httputil.NewResponseError(c, http.StatusForbidden, msgErr)
		return
	}

	if id == "" {
		httputil.NewResponseError(c, http.StatusBadRequest, msgErr)
		return
	}

	user, err := auth.srvAuth.FindByID(c.Request.Context(), helpers.StringToID(id))
	if err != nil {
		httputil.NewResponseError(c, http.StatusBadRequest, "user not found")
		return
	}

	// accessToken, err := createTokenAndSetHead(c, auth.managerToken, user)
	accessToken, err := createAccessToken(c, auth.managerToken, user)
	if err != nil {
		httputil.NewResponseError(c, http.StatusInternalServerError, err.Error())
		return
	}

	newRefreshToken, err := createRefreshToken(c, auth.managerToken, user.ID)
	if err != nil {
		httputil.NewResponseError(c, http.StatusInternalServerError, err.Error())
		return
	}

	httpresponsecredentials.NewResponseCredentials(c, http.StatusOK, user, accessToken, newRefreshToken)
}

// JWKS godoc
// @Summary      Request JWKS
// @Description  get JWKs
// @Tags         security
// @Accept       json
// @Produce      json
// @Success      200  {object}  models.PublicKeysParams
// @Failure      400    {object}  httputil.ResponseError
// @Router       /jwks [get]
func (auth *AuthController) JWKS(c *gin.Context) {
	ctx, span := trace.NewSpan(c.Request.Context(), "AuthController.JWKS")
	defer span.End()

	jwk, err := auth.managerSecurityKeys.GetPublicKeyParams(ctx)
	if err != nil {
		trace.AddSpanError(span, err)
		httputil.NewResponseError(c, http.StatusBadRequest, "error loading jwk")
		return
	}

	c.JSON(http.StatusOK, jwk)
}

// DownloadPublicKeyJWT godoc
// @Summary      Request an public key JWT
// @Description  get an public key JWT
// @Tags         security
// @Accept       json
// @Produce      json
// @Success      200  string        string                    "Return public key JWT"
// @Failure      500  {object}  httputil.ResponseError
// @Router       /download/public-key-jwt [get]
func (auth *AuthController) DownloadPublicKeyJWT(c *gin.Context) {
	_, span := trace.NewSpan(c.Request.Context(), "AuthController.DownloadPublicKeyJWT")
	defer span.End()

	_, err := os.Stat(auth.config.SecurityKeys.FileECPPublicKey)
	if err != nil {
		trace.AddSpanError(span, err)
		httputil.NewResponseError(c, http.StatusInternalServerError, "public key JWT file not found")
		return
	}

	c.File(auth.config.SecurityKeys.FileECPPublicKey)
}

// DownloadCertKey godoc
// @Summary      Request an key cert
// @Description  get an key cert
// @Tags         security
// @Accept       json
// @Produce      json
// @Param        password   path    string              true  "Password permission"
// @Success      200  string        string                    "Return key cert"
// @Failure      500  {object}  httputil.ResponseError
// @Router       /download/cert-key/{password} [get]
func (auth *AuthController) DownloadCertKey(c *gin.Context) {
	_, span := trace.NewSpan(c.Request.Context(), "AuthController.DownloadCertKey")
	defer span.End()

	password := c.Param("password")
	if password == "" {
		httputil.NewResponseError(c, http.StatusBadRequest, "invalid credentials")
		return
	}

	passwordPermission, err := base64.StdEncoding.DecodeString(password)
	if err != nil || passwordPermission == nil {
		httputil.NewResponseError(c, http.StatusBadRequest, "invalid credentials")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(auth.config.Certificates.HashPermissionEndPoint), []byte(passwordPermission)); err != nil {
		httputil.NewResponseError(c, http.StatusBadRequest, "invalid credentials")
		return
	}

	_, certKeyPath := auth.certificateServices.GetPathsCertificateHostAndKey()

	_, err = os.Stat(certKeyPath)
	if err != nil {
		trace.AddSpanError(span, err)
		httputil.NewResponseError(c, http.StatusInternalServerError, "public key cert file not found")
		return
	}

	c.File(certKeyPath)
}

// DownloadCert godoc
// @Summary      Request an certificate
// @Description  get an certificate
// @Tags         security
// @Accept       json
// @Produce      json
// @Param        password   path    string              true  "Password permission"
// @Success      200  string        string                    "Return certificate"
// @Failure      500    {object}  httputil.ResponseError
// @Router       /download/cert/{password} [get]
func (auth *AuthController) DownloadCert(c *gin.Context) {
	_, span := trace.NewSpan(c.Request.Context(), "AuthController.DownloadCert")
	defer span.End()

	password := c.Param("password")
	if password == "" {
		httputil.NewResponseError(c, http.StatusBadRequest, "invalid credentials")
		return
	}

	passwordPermission, err := base64.StdEncoding.DecodeString(password)
	if err != nil || passwordPermission == nil {
		httputil.NewResponseError(c, http.StatusBadRequest, "invalid credentials")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(auth.config.Certificates.HashPermissionEndPoint), passwordPermission); err != nil {
		httputil.NewResponseError(c, http.StatusBadRequest, "invalid credentials")
		return
	}

	pathCert, _ := auth.certificateServices.GetPathsCertificateHostAndKey()

	_, err = os.Stat(pathCert)
	if err != nil {
		trace.AddSpanError(span, err)
		httputil.NewResponseError(c, http.StatusInternalServerError, "certificate file not found")
		return
	}

	c.File(pathCert)
}

// DownloadCACert godoc
// @Summary      Request an CA certificate
// @Description  get an CA certificate
// @Tags         security
// @Accept       json
// @Produce      json
// @Param        password   path    string              true  "Password permission"
// @Success      200  string        string                    "Return certificate"
// @Failure      500    {object}  httputil.ResponseError
// @Router       /download/cacert/{password} [get]
func (auth *AuthController) DownloadCACert(c *gin.Context) {
	_, span := trace.NewSpan(c.Request.Context(), "AuthController.DownloadCACert")
	defer span.End()

	password := c.Param("password")
	if password == "" {
		httputil.NewResponseError(c, http.StatusBadRequest, "invalid credentials")
		return
	}

	passwordPermission, err := base64.StdEncoding.DecodeString(password)
	if err != nil || passwordPermission == nil {
		httputil.NewResponseError(c, http.StatusBadRequest, "invalid credentials")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(auth.config.Certificates.HashPermissionEndPoint), passwordPermission); err != nil {
		httputil.NewResponseError(c, http.StatusBadRequest, "invalid credentials")
		return
	}

	pathCACert, _ := auth.certificateServices.GetPathsCertificateCAAndKey()

	_, err = os.Stat(pathCACert)
	if err != nil {
		trace.AddSpanError(span, err)
		httputil.NewResponseError(c, http.StatusInternalServerError, "certificate CA file not found")
		return
	}

	c.File(pathCACert)
}

func mapToUserDTO(user *models.User) *dtos.User {
	return &dtos.User{
		ID:        user.ID.Hex(),
		Email:     user.Email,
		Claims:    []common_models.Claims(user.Claims),
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Version:   user.Version,
	}
}

func createAccessToken(c *gin.Context, managerToken *jwt.ManagerToken, user *models.User) (string, error) {
	accessToken, err := managerToken.CreateAccessToken(c, user)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

// func createTokenAndSetHead(c *gin.Context, managerToken *jwt.ManagerToken, user *models.User) (string, error) {
// 	accessToken, err := managerToken.CreateAccessToken(c, user)
// 	if err != nil {
// 		return "", err
// 	}

// 	managerToken.SetAccessTokenToHead(c, accessToken)

// 	return accessToken, nil
// }

// func removeCookieAccessToken(c *gin.Context, managerToken *jwt.ManagerToken) {
// 	managerToken.RemoveHeadAccessToken(c)
// }

func createRefreshToken(c *gin.Context, managerToken *jwt.ManagerToken, ID primitive.ObjectID) (string, error) {
	refreshToken, err := managerToken.CreateRefreshToken(c, ID)
	if err != nil {
		return "", err
	}

	return refreshToken, nil
}

// func (auth *AuthController) addLog(method string) *logrus.Entry {
// 	return auth.logger.WithFields(logrus.Fields{"controller": "api/auth", "method": method})
// }

func (auth *AuthController) Pub(c *gin.Context) {
	ctx, span := trace.NewSpan(c.Request.Context(), "AuthController.Pub")
	defer span.End()

	user := &models.User{}
	if err := c.BindJSON(user); err != nil {
		httputil.NewResponseError(c, http.StatusBadRequest, err.Error())
		return
	}

	user.Deleted = true

	data, err := json.Marshal(user)
	if err != nil {
		trace.FailSpan(span, "Error json parse")
		log.Printf("Error json parse: %v", err)
	}

	_, span = trace.NewSpan(ctx, "publish.userDeleted")
	defer span.End()
	err = auth.publisher.Publish(string(common_nats.UserDeleted), data)
	if err != nil {
		auth.natsMetrics.ErrorPublish()
		log.Printf("Error publisher: %v", err)
		return
	}

	auth.natsMetrics.SuccessPublishUserDeleted()
	log.Println("UserDeleted Published!!!")
}
