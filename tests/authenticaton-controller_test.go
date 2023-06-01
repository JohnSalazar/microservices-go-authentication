package tests

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"authentication/src/dtos"
	"authentication/src/models"

	httpresponsecredentials "authentication/src/http"

	"github.com/gin-gonic/gin"
	"github.com/oceano-dev/microservices-go-common/helpers"
	"github.com/oceano-dev/microservices-go-common/httputil"
	common_models "github.com/oceano-dev/microservices-go-common/models"
	"github.com/stretchr/testify/assert"
)

func TestSignupSuccess(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	w, _ := submitSignup()

	response := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(w.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, w.Result().StatusCode, 201)
	assert.NotEmpty(t, response.RefreshToken)
	assert.NotNil(t, w)
	assert.NoError(t, err)
}

func TestSignupEmailError(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	signup := &dtos.SignUp{
		Password:        "123456",
		PasswordConfirm: "123456",
	}

	body, _ := json.Marshal(signup)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/signup", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	response := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(w.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, w.Result().StatusCode, 400)
	assert.NotNil(t, w)
	assert.NoError(t, err)
}

func TestSignupPasswordError(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	signup := &dtos.SignUp{
		Email:           "user1@gmail.com",
		PasswordConfirm: "123456",
	}

	body, _ := json.Marshal(signup)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/signup", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	response := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(w.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, w.Result().StatusCode, 400)
	assert.NotNil(t, w)
	assert.NoError(t, err)
}

func TestSignupPasswordConfirmError(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	signup := &dtos.SignUp{
		Email:    "user1@gmail.com",
		Password: "123456",
	}

	body, _ := json.Marshal(signup)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/signup", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	response := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(w.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, w.Result().StatusCode, 400)
	assert.NotNil(t, w)
	assert.NoError(t, err)
}

func TestSigninSuccess(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	submitSignup()

	signin := &dtos.SignIn{
		Email:    "user1@gmail.com",
		Password: "123456",
	}

	bodySignin, _ := json.Marshal(signin)

	reqSignin, _ := http.NewRequest(http.MethodPost, "/api/v1/signin", bytes.NewBuffer(bodySignin))
	reqSignin.Header.Set("Content-Type", "application/json; charset=UTF-8")

	wSignin := httptest.NewRecorder()
	router.ServeHTTP(wSignin, reqSignin)

	response := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(wSignin.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, wSignin.Result().StatusCode, 200)
	assert.NotEmpty(t, response.RefreshToken)
	assert.NotNil(t, wSignin)
	assert.NoError(t, err)
}

func TestSigninEmailError(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	submitSignup()

	signin := &dtos.SignIn{
		Password: "123456",
	}

	bodySignin, _ := json.Marshal(signin)

	reqSignin, _ := http.NewRequest(http.MethodPost, "/api/v1/signin", bytes.NewBuffer(bodySignin))
	reqSignin.Header.Set("Content-Type", "application/json; charset=UTF-8")

	wSignin := httptest.NewRecorder()
	router.ServeHTTP(wSignin, reqSignin)

	response := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(wSignin.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, wSignin.Result().StatusCode, 400)
	assert.NotNil(t, wSignin)
	assert.NoError(t, err)
}

func TestSigninPasswordError(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	submitSignup()

	signin := &dtos.SignIn{
		Email: "user1@gmail.com",
	}

	bodySignin, _ := json.Marshal(signin)

	reqSignin, _ := http.NewRequest(http.MethodPost, "/api/v1/signin", bytes.NewBuffer(bodySignin))
	reqSignin.Header.Set("Content-Type", "application/json; charset=UTF-8")

	wSignin := httptest.NewRecorder()
	router.ServeHTTP(wSignin, reqSignin)

	response := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(wSignin.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, wSignin.Result().StatusCode, 400)
	assert.NotNil(t, wSignin)
	assert.NoError(t, err)
}

func TestCreateUserSuccess(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	managerSecurityKeys.GetAllPublicKeys()

	wSubmitSignup, signup := submitSignup()

	rSubmitSignup := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(wSubmitSignup.Body.Bytes(), rSubmitSignup)
	if err != nil {
		t.Error(err)
	}

	userModel := &models.User{
		ID: rSubmitSignup.User.Id,
		Claims: []common_models.Claims{
			{Type: "admin", Value: "create"},
		},
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	authService.UpdateClaims(ctx, userModel)

	bodySignup, _ := json.Marshal(signup)

	reqSignin, _ := http.NewRequest(http.MethodPost, "/api/v1/signin", bytes.NewBuffer(bodySignup))
	reqSignin.Header.Set("Content-Type", "application/json; charset=UTF-8")

	wSignin := httptest.NewRecorder()
	router.ServeHTTP(wSignin, reqSignin)

	responseSignin := &httpresponsecredentials.ResponseCredentials{}
	err = json.Unmarshal(wSignin.Body.Bytes(), responseSignin)
	if err != nil {
		t.Error(err)
	}

	claim := common_models.Claims{
		Type:  "user",
		Value: "read",
	}
	user := &dtos.CreateUser{
		Email:    "newuser@email.com",
		Password: "123456",
		Claims:   []common_models.Claims{claim},
	}

	body, _ := json.Marshal(user)

	reqUser, _ := http.NewRequest(http.MethodPost, "/api/v1/user", bytes.NewBuffer(body))
	reqUser.Header.Set("Content-Type", "application/json; charset=UTF-8")
	reqUser.Header.Set("Authorization", "Bearer "+responseSignin.AccessToken)

	wUser := httptest.NewRecorder()
	router.ServeHTTP(wUser, reqUser)

	response := &dtos.UserCredentials{}
	err = json.Unmarshal(wUser.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, wUser.Result().StatusCode, 201)
	assert.NotEmpty(t, response)
	assert.NotNil(t, wUser)
	assert.NoError(t, err)
}

func TestCreateUserError(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	managerSecurityKeys.GetAllPublicKeys()

	wSubmitSignup, signup := submitSignup()

	rSubmitSignup := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(wSubmitSignup.Body.Bytes(), rSubmitSignup)
	if err != nil {
		t.Error(err)
	}

	userModel := &models.User{
		ID: rSubmitSignup.User.Id,
		Claims: []common_models.Claims{
			{Type: "admin", Value: "create"},
		},
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	authService.UpdateClaims(ctx, userModel)

	bodySignup, _ := json.Marshal(signup)

	reqSignin, _ := http.NewRequest(http.MethodPost, "/api/v1/signin", bytes.NewBuffer(bodySignup))
	reqSignin.Header.Set("Content-Type", "application/json; charset=UTF-8")

	wSignin := httptest.NewRecorder()
	router.ServeHTTP(wSignin, reqSignin)

	responseSignin := &httpresponsecredentials.ResponseCredentials{}
	err = json.Unmarshal(wSignin.Body.Bytes(), responseSignin)
	if err != nil {
		t.Error(err)
	}

	claim := &common_models.Claims{
		Type:  "user",
		Value: "read",
	}
	user := &dtos.CreateUser{
		Email:    "user1@gmail.com",
		Password: "123456",
		Claims:   []common_models.Claims{*claim},
	}

	body, _ := json.Marshal(user)

	reqUser, _ := http.NewRequest(http.MethodPost, "/api/v1/user", bytes.NewBuffer(body))
	reqUser.Header.Set("Content-Type", "application/json; charset=UTF-8")
	reqUser.Header.Set("Authorization", "Bearer "+responseSignin.AccessToken)

	wUser := httptest.NewRecorder()
	router.ServeHTTP(wUser, reqUser)

	response := &dtos.UserCredentials{}
	err = json.Unmarshal(wUser.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, wUser.Result().StatusCode, 400)
	assert.NotNil(t, wUser)
	assert.NoError(t, err)
}

func TestCreateUserNotAuthorized(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	managerSecurityKeys.GetAllPublicKeys()

	wSubmitSignup, signup := submitSignup()

	rSubmitSignup := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(wSubmitSignup.Body.Bytes(), rSubmitSignup)
	if err != nil {
		t.Error(err)
	}

	userModel := &models.User{
		ID: rSubmitSignup.User.Id,
		Claims: []common_models.Claims{
			{Type: "admin", Value: "read"},
		},
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	authService.UpdateClaims(ctx, userModel)

	bodySignup, _ := json.Marshal(signup)

	reqSignin, _ := http.NewRequest(http.MethodPost, "/api/v1/signin", bytes.NewBuffer(bodySignup))
	reqSignin.Header.Set("Content-Type", "application/json; charset=UTF-8")

	wSignin := httptest.NewRecorder()
	router.ServeHTTP(wSignin, reqSignin)

	responseSignin := &httpresponsecredentials.ResponseCredentials{}
	err = json.Unmarshal(wSignin.Body.Bytes(), responseSignin)
	if err != nil {
		t.Error(err)
	}

	claim := &common_models.Claims{
		Type:  "user",
		Value: "read",
	}
	user := &dtos.CreateUser{
		Email:    "newuser@gmail.com",
		Password: "123456",
		Claims:   []common_models.Claims{*claim},
	}

	body, _ := json.Marshal(user)

	reqUser, _ := http.NewRequest(http.MethodPost, "/api/v1/user", bytes.NewBuffer(body))
	reqUser.Header.Set("Content-Type", "application/json; charset=UTF-8")
	reqUser.Header.Set("Authorization", "Bearer "+responseSignin.AccessToken)

	wUser := httptest.NewRecorder()
	router.ServeHTTP(wUser, reqUser)

	response := &dtos.UserCredentials{}
	err = json.Unmarshal(wUser.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, wUser.Result().StatusCode, 403)
	assert.NotNil(t, wUser)
	assert.NoError(t, err)
}

func TestGetUsersWithClaimSuccess(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	managerSecurityKeys.GetAllPublicKeys()

	wSubmitSignup, signup := submitSignup()

	rSubmitSignup := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(wSubmitSignup.Body.Bytes(), rSubmitSignup)
	if err != nil {
		t.Error(err)
	}

	userModel := &models.User{
		ID: rSubmitSignup.User.Id,
		Claims: []common_models.Claims{
			{Type: "user", Value: "read,write"},
			{Type: "admin", Value: "read,write"},
		},
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	authService.UpdateClaims(ctx, userModel)

	bodySignup, _ := json.Marshal(signup)

	reqSignin, _ := http.NewRequest(http.MethodPost, "/api/v1/signin", bytes.NewBuffer(bodySignup))
	reqSignin.Header.Set("Content-Type", "application/json; charset=UTF-8")

	wSignin := httptest.NewRecorder()
	router.ServeHTTP(wSignin, reqSignin)

	responseSignin := &httpresponsecredentials.ResponseCredentials{}
	err = json.Unmarshal(wSignin.Body.Bytes(), responseSignin)
	if err != nil {
		t.Error(err)
	}

	reqUsers, _ := http.NewRequest(http.MethodGet, "/api/v1/"+responseSignin.User.Email+"/1/1", nil)
	reqUsers.Header.Set("Content-Type", "application/json; charset=UTF-8")
	reqUsers.Header.Set("Authorization", "Bearer "+responseSignin.AccessToken)

	wUsers := httptest.NewRecorder()
	router.ServeHTTP(wUsers, reqUsers)

	var response []dtos.User
	err = json.Unmarshal(wUsers.Body.Bytes(), &response)
	if err != nil {
		t.Error(err)
	}

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, response[0].Email, responseSignin.User.Email)
}

func TestProfileSuccess(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	managerSecurityKeys.GetAllPublicKeys()

	wSubmitSignup, signup := submitSignup()

	rSubmitSignup := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(wSubmitSignup.Body.Bytes(), rSubmitSignup)
	if err != nil {
		t.Error(err)
	}

	userModel := &models.User{
		ID: rSubmitSignup.User.Id,
		Claims: []common_models.Claims{
			{Type: "user", Value: "read,write"},
			{Type: "admin", Value: "read,write"},
		},
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	authService.UpdateClaims(ctx, userModel)

	bodySignup, _ := json.Marshal(signup)

	reqSignin, _ := http.NewRequest(http.MethodPost, "/api/v1/signin", bytes.NewBuffer(bodySignup))
	reqSignin.Header.Set("Content-Type", "application/json; charset=UTF-8")

	wSignin := httptest.NewRecorder()
	router.ServeHTTP(wSignin, reqSignin)

	responseSignin := &httpresponsecredentials.ResponseCredentials{}
	err = json.Unmarshal(wSignin.Body.Bytes(), responseSignin)
	if err != nil {
		t.Error(err)
	}

	reqProfile, _ := http.NewRequest(http.MethodGet, "/api/v1/profile", nil)
	reqProfile.Header.Set("Content-Type", "application/json; charset=UTF-8")
	reqProfile.Header.Set("Authorization", "Bearer "+responseSignin.AccessToken)

	// reqProfile.AddCookie(wSignin.Result().Cookies()[0])

	wProfile := httptest.NewRecorder()
	router.ServeHTTP(wProfile, reqProfile)

	response := &dtos.User{}
	err = json.Unmarshal(wProfile.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.NoError(t, err)
	assert.NotNil(t, response.ID)
	assert.Greater(t, len(response.Claims), 0)
}

func TestProfileNotAuthorized(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	managerSecurityKeys.GetAllPublicKeys()

	wSubmitSignup, signin := submitSignup()

	rSubmitSignup := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(wSubmitSignup.Body.Bytes(), rSubmitSignup)
	if err != nil {
		t.Error(err)
	}

	userModel := &models.User{
		ID: rSubmitSignup.User.Id,
		Claims: []common_models.Claims{
			{Type: "user", Value: "read,write"},
		},
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	authService.UpdateClaims(ctx, userModel)

	bodySignin, _ := json.Marshal(signin)

	reqSignin, _ := http.NewRequest(http.MethodPost, "/api/v1/signin", bytes.NewBuffer(bodySignin))
	reqSignin.Header.Set("Content-Type", "application/json; charset=UTF-8")

	wSignin := httptest.NewRecorder()
	router.ServeHTTP(wSignin, reqSignin)

	responseSignin := &httpresponsecredentials.ResponseCredentials{}
	err = json.Unmarshal(wSignin.Body.Bytes(), responseSignin)
	if err != nil {
		t.Error(err)
	}

	reqProfile, _ := http.NewRequest(http.MethodGet, "/api/v1/profile", nil)
	reqProfile.Header.Set("Content-Type", "application/json; charset=UTF-8")
	// reqProfile.Header.Set("Authorization", "Bearer "+responseSignin.AccessToken)

	// reqProfile.AddCookie(wSignin.Result().Cookies()[0])

	wProfile := httptest.NewRecorder()
	router.ServeHTTP(wProfile, reqProfile)

	response := &dtos.User{}
	err = json.Unmarshal(wProfile.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.NoError(t, err)
	assert.Equal(t, wProfile.Result().StatusCode, 401)
}

// func TestProfileError(t *testing.T) {
// 	// CleanMongoCollection(usersCollection)
// 	userRepository.ClearCollection()

// 	wSubmitSignup, signin := submitSignup()

// 	rSubmitSignup := &httpresponsecredentials.ResponseCredentials{}
// 	err := json.Unmarshal(wSubmitSignup.Body.Bytes(), rSubmitSignup)
// 	if err != nil {
// 		t.Error(err)
// 	}

// 	bodySignin, _ := json.Marshal(signin)

// 	reqSignin, _ := http.NewRequest(http.MethodPost, "/api/v1/signin", bytes.NewBuffer(bodySignin))
// 	reqSignin.Header.Set("Content-Type", "application/json; charset=UTF-8")

// 	wSignin := httptest.NewRecorder()
// 	router.ServeHTTP(wSignin, reqSignin)

// 	responseSignin := &httpresponsecredentials.ResponseCredentials{}
// 	err = json.Unmarshal(wSignin.Body.Bytes(), responseSignin)
// 	if err != nil {
// 		t.Error(err)
// 	}

// 	reqProfile, _ := http.NewRequest(http.MethodGet, "/api/v1/profile", nil)
// 	reqProfile.Header.Set("Content-Type", "application/json; charset=UTF-8")
// 	reqProfile.Header.Set("Authorization", "Bearer "+responseSignin.AccessToken)

// 	// reqProfile.AddCookie(wSignin.Result().Cookies()[0])

// 	wProfile := httptest.NewRecorder()
// 	router.ServeHTTP(wProfile, reqProfile)

// 	response := &dtos.User{}
// 	err = json.Unmarshal(wProfile.Body.Bytes(), response)
// 	if err != nil {
// 		t.Error(err)
// 	}

// 	assert.Equal(t, wProfile.Result().StatusCode, 401)
// 	assert.NoError(t, err)
// 	assert.Empty(t, response.ID)
// 	assert.Equal(t, len(response.Claims), 0)
// }

func TestUpdateEmailSuccess(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	managerSecurityKeys.GetAllPublicKeys()

	wSignup, _ := submitSignup()

	rSubmitSignup := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(wSignup.Body.Bytes(), rSubmitSignup)
	if err != nil {
		t.Error(err)
	}

	updateEmailDTO := &dtos.UpdateEmail{
		ID:    rSubmitSignup.User.Id.Hex(),
		Email: "usuario2@gmail.com",
	}

	bodyUpdateEmail, _ := json.Marshal(updateEmailDTO)

	reqUpdateEmail, _ := http.NewRequest(http.MethodPut, "/api/v1/email/"+updateEmailDTO.ID, bytes.NewBuffer(bodyUpdateEmail))
	reqUpdateEmail.Header.Set("Content-Type", "application/json; charset=UTF-8")
	reqUpdateEmail.Header.Set("Authorization", "Bearer "+rSubmitSignup.AccessToken)

	// reqUpdateEmail.AddCookie(cookie)

	wUpdateEmail := httptest.NewRecorder()
	router.ServeHTTP(wUpdateEmail, reqUpdateEmail)

	response := &httpresponsecredentials.ResponseCredentials{}
	err = json.Unmarshal(wUpdateEmail.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, wUpdateEmail.Result().StatusCode, 200)
	assert.NotEqual(t, rSubmitSignup.User.Email, response.User.Email)
}

func TestUpdateEmailIDError(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	managerSecurityKeys.GetAllPublicKeys()

	wSignup, _ := submitSignup()

	rSubmitSignup := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(wSignup.Body.Bytes(), rSubmitSignup)
	if err != nil {
		t.Error(err)
	}

	updateEmailDTO := &dtos.UpdateEmail{
		ID:    "ID",
		Email: "usuario2@gmail.com",
	}

	bodyUpdateEmail, _ := json.Marshal(updateEmailDTO)

	reqUpdateEmail, _ := http.NewRequest(http.MethodPut, "/api/v1/email/"+updateEmailDTO.ID, bytes.NewBuffer(bodyUpdateEmail))
	reqUpdateEmail.Header.Set("Content-Type", "application/json; charset=UTF-8")
	reqUpdateEmail.Header.Set("Authorization", "Bearer "+rSubmitSignup.AccessToken)

	// reqUpdateEmail.AddCookie(cookie)

	wUpdateEmail := httptest.NewRecorder()
	router.ServeHTTP(wUpdateEmail, reqUpdateEmail)

	response := &httpresponsecredentials.ResponseCredentials{}
	err = json.Unmarshal(wUpdateEmail.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, wUpdateEmail.Result().StatusCode, 400)
}

func TestUpdateEmailError(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	managerSecurityKeys.GetAllPublicKeys()

	wSignup, _ := submitSignup()

	rSubmitSignup := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(wSignup.Body.Bytes(), rSubmitSignup)
	if err != nil {
		t.Error(err)
	}

	updateEmailDTO := &dtos.UpdateEmail{
		ID: rSubmitSignup.User.Id.Hex(),
	}

	bodyUpdateEmail, _ := json.Marshal(updateEmailDTO)

	reqUpdateEmail, _ := http.NewRequest(http.MethodPut, "/api/v1/email/"+updateEmailDTO.ID, bytes.NewBuffer(bodyUpdateEmail))
	reqUpdateEmail.Header.Set("Content-Type", "application/json; charset=UTF-8")
	reqUpdateEmail.Header.Set("Authorization", "Bearer "+rSubmitSignup.AccessToken)

	// reqUpdateEmail.AddCookie(cookie)

	wUpdateEmail := httptest.NewRecorder()
	router.ServeHTTP(wUpdateEmail, reqUpdateEmail)

	response := &httpresponsecredentials.ResponseCredentials{}
	err = json.Unmarshal(wUpdateEmail.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, wUpdateEmail.Result().StatusCode, 400)
}

func TestRequestUpdatePasswordSuccess(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	_, dtoSignup := submitSignup()

	requestUpdatePasswordDTO := &dtos.RequestUpdatePassword{
		Email: dtoSignup.Email,
	}

	bodyRequestUpdatePassword, _ := json.Marshal(requestUpdatePasswordDTO)

	reqRequestUpdatePassword, _ := http.NewRequest(http.MethodPost, "/api/v1/request-update-password", bytes.NewBuffer(bodyRequestUpdatePassword))
	reqRequestUpdatePassword.Header.Set("Content-Type", "application/json; charset=UTF-8")

	wRequestUpdatePassword := httptest.NewRecorder()
	router.ServeHTTP(wRequestUpdatePassword, reqRequestUpdatePassword)

	response := &httputil.ResponseSuccess{}
	err := json.Unmarshal(wRequestUpdatePassword.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, wRequestUpdatePassword.Result().StatusCode, 201)
	assert.Equal(t, response.Message, "check your email")
}

func TestRequestUpdatePasswordError(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	submitSignup()

	requestUpdatePasswordDTO := &dtos.RequestUpdatePassword{}

	bodyRequestUpdatePassword, _ := json.Marshal(requestUpdatePasswordDTO)

	reqRequestUpdatePassword, _ := http.NewRequest(http.MethodPost, "/api/v1/request-update-password", bytes.NewBuffer(bodyRequestUpdatePassword))
	reqRequestUpdatePassword.Header.Set("Content-Type", "application/json; charset=UTF-8")

	wRequestUpdatePassword := httptest.NewRecorder()
	router.ServeHTTP(wRequestUpdatePassword, reqRequestUpdatePassword)

	response := &httputil.ResponseSuccess{}
	err := json.Unmarshal(wRequestUpdatePassword.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, wRequestUpdatePassword.Result().StatusCode, 400)
}

func TestUpdatePasswordSuccess(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	managerSecurityKeys.GetAllPublicKeys()

	wSignup, dtoSignup := submitSignup()

	rSubmitSignup := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(wSignup.Body.Bytes(), rSubmitSignup)
	if err != nil {
		t.Error(err)
	}

	requestCodeService.CreateCode(context.Background(), dtoSignup.Email)
	time.Sleep(1 * time.Second)

	code := emailServiceMock.GetCode()

	updatePasswordDTO := &dtos.UpdatePassword{
		Email:                     dtoSignup.Email,
		Password:                  "1234567",
		PasswordConfirm:           "1234567",
		RequestUpdatePasswordCode: code,
	}

	bodyUpdatePassword, _ := json.Marshal(updatePasswordDTO)

	reqUpdatePassword, _ := http.NewRequest(http.MethodPut, "/api/v1/password/"+updatePasswordDTO.Email, bytes.NewBuffer(bodyUpdatePassword))
	reqUpdatePassword.Header.Set("Content-Type", "application/json; charset=UTF-8")

	wUpdatePassword := httptest.NewRecorder()
	router.ServeHTTP(wUpdatePassword, reqUpdatePassword)

	response := &httpresponsecredentials.ResponseCredentials{}
	err = json.Unmarshal(wUpdatePassword.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, wUpdatePassword.Result().StatusCode, 200)
}

func TestUpdatePasswordEmailError(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	managerSecurityKeys.GetAllPublicKeys()

	wSignup, dtoSignup := submitSignup()

	rSubmitSignup := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(wSignup.Body.Bytes(), rSubmitSignup)
	if err != nil {
		t.Error(err)
	}

	requestCodeService.CreateCode(context.Background(), dtoSignup.Email)
	time.Sleep(1 * time.Second)

	code := emailServiceMock.GetCode()

	updatePasswordDTO := &dtos.UpdatePassword{
		Email:                     "email",
		Password:                  "1234567",
		PasswordConfirm:           "1234567",
		RequestUpdatePasswordCode: code,
	}

	bodyUpdatePassword, _ := json.Marshal(updatePasswordDTO)

	reqUpdatePassword, _ := http.NewRequest(http.MethodPut, "/api/v1/password/"+updatePasswordDTO.Email, bytes.NewBuffer(bodyUpdatePassword))
	reqUpdatePassword.Header.Set("Content-Type", "application/json; charset=UTF-8")

	wUpdatePassword := httptest.NewRecorder()
	router.ServeHTTP(wUpdatePassword, reqUpdatePassword)

	response := &httpresponsecredentials.ResponseCredentials{}
	err = json.Unmarshal(wUpdatePassword.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, wUpdatePassword.Result().StatusCode, 400)
}

func TestUpdatePasswordError(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	managerSecurityKeys.GetAllPublicKeys()

	wSignup, dtoSignup := submitSignup()

	rSubmitSignup := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(wSignup.Body.Bytes(), rSubmitSignup)
	if err != nil {
		t.Error(err)
	}

	requestCodeService.CreateCode(context.Background(), dtoSignup.Email)
	time.Sleep(1 * time.Second)

	code := emailServiceMock.GetCode()

	updatePasswordDTO := &dtos.UpdatePassword{
		Email:                     dtoSignup.Email,
		PasswordConfirm:           "1234567",
		RequestUpdatePasswordCode: code,
	}

	bodyUpdatePassword, _ := json.Marshal(updatePasswordDTO)

	reqUpdatePassword, _ := http.NewRequest(http.MethodPut, "/api/v1/password/"+updatePasswordDTO.Email, bytes.NewBuffer(bodyUpdatePassword))
	reqUpdatePassword.Header.Set("Content-Type", "application/json; charset=UTF-8")

	wUpdatePassword := httptest.NewRecorder()
	router.ServeHTTP(wUpdatePassword, reqUpdatePassword)

	response := &httpresponsecredentials.ResponseCredentials{}
	err = json.Unmarshal(wUpdatePassword.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, wUpdatePassword.Result().StatusCode, 400)
}

func TestUpdatePasswordConfirmPasswordError(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	managerSecurityKeys.GetAllPublicKeys()

	wSignup, dtoSignup := submitSignup()

	rSubmitSignup := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(wSignup.Body.Bytes(), rSubmitSignup)
	if err != nil {
		t.Error(err)
	}

	requestCodeService.CreateCode(context.Background(), dtoSignup.Email)
	time.Sleep(1 * time.Second)

	code := emailServiceMock.GetCode()

	updatePasswordDTO := &dtos.UpdatePassword{
		Email:                     dtoSignup.Email,
		Password:                  "1234567",
		RequestUpdatePasswordCode: code,
	}

	bodyUpdatePassword, _ := json.Marshal(updatePasswordDTO)

	reqUpdatePassword, _ := http.NewRequest(http.MethodPut, "/api/v1/password/"+updatePasswordDTO.Email, bytes.NewBuffer(bodyUpdatePassword))
	reqUpdatePassword.Header.Set("Content-Type", "application/json; charset=UTF-8")

	wUpdatePassword := httptest.NewRecorder()
	router.ServeHTTP(wUpdatePassword, reqUpdatePassword)

	response := &httpresponsecredentials.ResponseCredentials{}
	err = json.Unmarshal(wUpdatePassword.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, wUpdatePassword.Result().StatusCode, 400)
}

func TestUpdatePasswordCodeError(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	managerSecurityKeys.GetAllPublicKeys()

	wSignup, dtoSignup := submitSignup()

	rSubmitSignup := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(wSignup.Body.Bytes(), rSubmitSignup)
	if err != nil {
		t.Error(err)
	}

	updatePasswordDTO := &dtos.UpdatePassword{
		Email:           dtoSignup.Email,
		Password:        "1234567",
		PasswordConfirm: "1234567",
	}

	bodyUpdatePassword, _ := json.Marshal(updatePasswordDTO)

	reqUpdatePassword, _ := http.NewRequest(http.MethodPut, "/api/v1/password/"+updatePasswordDTO.Email, bytes.NewBuffer(bodyUpdatePassword))
	reqUpdatePassword.Header.Set("Content-Type", "application/json; charset=UTF-8")

	wUpdatePassword := httptest.NewRecorder()
	router.ServeHTTP(wUpdatePassword, reqUpdatePassword)

	response := &httpresponsecredentials.ResponseCredentials{}
	err = json.Unmarshal(wUpdatePassword.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, wUpdatePassword.Result().StatusCode, 400)
}

func TestUpdatePasswordOtherEmailError(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	managerSecurityKeys.GetAllPublicKeys()

	wSignup, dtoSignup := submitSignup()

	rSubmitSignup := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(wSignup.Body.Bytes(), rSubmitSignup)
	if err != nil {
		t.Error(err)
	}

	requestCodeService.CreateCode(context.Background(), dtoSignup.Email)
	time.Sleep(1 * time.Second)

	code := emailServiceMock.GetCode()

	updatePasswordDTO := &dtos.UpdatePassword{
		Email:                     "usuario2@gmail.com",
		Password:                  "1234567",
		PasswordConfirm:           "1234567",
		RequestUpdatePasswordCode: code,
	}

	bodyUpdatePassword, _ := json.Marshal(updatePasswordDTO)

	reqUpdatePassword, _ := http.NewRequest(http.MethodPut, "/api/v1/password/"+updatePasswordDTO.Email, bytes.NewBuffer(bodyUpdatePassword))
	reqUpdatePassword.Header.Set("Content-Type", "application/json; charset=UTF-8")

	wUpdatePassword := httptest.NewRecorder()
	router.ServeHTTP(wUpdatePassword, reqUpdatePassword)

	response := &httpresponsecredentials.ResponseCredentials{}
	err = json.Unmarshal(wUpdatePassword.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, wUpdatePassword.Result().StatusCode, 400)
}

func TestUpdateClaimsSuccess(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	managerSecurityKeys.GetAllPublicKeys()

	wSubmitSignup, signin := submitSignup()

	rSubmitSignup := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(wSubmitSignup.Body.Bytes(), rSubmitSignup)
	if err != nil {
		t.Error(err)
	}

	userModel := &models.User{
		ID: rSubmitSignup.User.Id,
		Claims: []common_models.Claims{
			{Type: "user", Value: "read,write"},
			{Type: "admin", Value: "create,update"},
		},
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	authService.UpdateClaims(ctx, userModel)

	bodySignin, _ := json.Marshal(signin)

	reqSignin, _ := http.NewRequest(http.MethodPost, "/api/v1/signin", bytes.NewBuffer(bodySignin))
	reqSignin.Header.Set("Content-Type", "application/json; charset=UTF-8")

	wSignin := httptest.NewRecorder()
	router.ServeHTTP(wSignin, reqSignin)

	responseSignin := &httpresponsecredentials.ResponseCredentials{}
	err = json.Unmarshal(wSignin.Body.Bytes(), responseSignin)
	if err != nil {
		t.Error(err)
	}

	updateClaims := &dtos.UpdateClaims{
		ID:      responseSignin.User.Id.Hex(),
		Claims:  []common_models.Claims{{Type: "admin", Value: "create,update"}},
		Version: 1,
	}

	bodyUpdateClaims, _ := json.Marshal(updateClaims)

	// reqSignin, _ = http.NewRequest(http.MethodPost, "/api/v1/signin", bytes.NewBuffer(bodySignin))
	// reqSignin.Header.Set("Content-Type", "application/json; charset=UTF-8")

	// wSignin = httptest.NewRecorder()
	// router.ServeHTTP(wSignin, reqSignin)

	// responseSignin = &httpresponsecredentials.ResponseCredentials{}
	// err = json.Unmarshal(wSignin.Body.Bytes(), responseSignin)
	// if err != nil {
	// 	t.Error(err)
	// }

	reqUpdateClaims, _ := http.NewRequest(http.MethodPut, "/api/v1/claims/"+updateClaims.ID, bytes.NewBuffer(bodyUpdateClaims))
	reqUpdateClaims.Header.Set("Content-Type", "application/json; charset=UTF-8")
	reqUpdateClaims.Header.Set("Authorization", "Bearer "+responseSignin.AccessToken)

	// reqUpdateClaims.AddCookie(wSignin.Result().Cookies()[0])

	wUpdateClaims := httptest.NewRecorder()
	router.ServeHTTP(wUpdateClaims, reqUpdateClaims)

	response := &httpresponsecredentials.ResponseCredentials{}
	err = json.Unmarshal(wUpdateClaims.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, wUpdateClaims.Code, 200)
	assert.NotEmpty(t, response.RefreshToken)
}

func TestUpdateClaimsNotAuthorized(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	managerSecurityKeys.GetAllPublicKeys()

	wSubmitSignup, signin := submitSignup()

	rSubmitSignup := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(wSubmitSignup.Body.Bytes(), rSubmitSignup)
	if err != nil {
		t.Error(err)
	}

	userModel := &models.User{
		ID: rSubmitSignup.User.Id,
		Claims: []common_models.Claims{
			{Type: "user", Value: "read,write"},
		},
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	authService.UpdateClaims(ctx, userModel)

	bodySignin, _ := json.Marshal(signin)

	reqSignin, _ := http.NewRequest(http.MethodPost, "/api/v1/signin", bytes.NewBuffer(bodySignin))
	reqSignin.Header.Set("Content-Type", "application/json; charset=UTF-8")

	wSignin := httptest.NewRecorder()
	router.ServeHTTP(wSignin, reqSignin)

	responseSignin := &httpresponsecredentials.ResponseCredentials{}
	err = json.Unmarshal(wSignin.Body.Bytes(), responseSignin)
	if err != nil {
		t.Error(err)
	}

	updateClaims := &dtos.UpdateClaims{
		ID: responseSignin.User.Id.Hex(),
		Claims: []common_models.Claims{
			{Type: "admin", Value: "read,write"},
		},
		Version: 1,
	}

	bodyUpdateClaims, _ := json.Marshal(updateClaims)

	reqUpdateClaims, _ := http.NewRequest(http.MethodPut, "/api/v1/claims/"+updateClaims.ID, bytes.NewBuffer(bodyUpdateClaims))
	reqUpdateClaims.Header.Set("Content-Type", "application/json; charset=UTF-8")
	reqUpdateClaims.Header.Set("Authorization", "Bearer "+responseSignin.AccessToken)

	// reqUpdateClaims.AddCookie(wSignin.Result().Cookies()[0])

	wUpdateClaims := httptest.NewRecorder()
	router.ServeHTTP(wUpdateClaims, reqUpdateClaims)

	response := &httpresponsecredentials.ResponseCredentials{}
	err = json.Unmarshal(wUpdateClaims.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, wUpdateClaims.Code, 403)
}

func TestDeleteSuccess(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	managerSecurityKeys.GetAllPublicKeys()

	wSubmitSignup, _ := submitSignup()

	rSubmitSignup := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(wSubmitSignup.Body.Bytes(), rSubmitSignup)
	if err != nil {
		t.Error(err)
	}

	reqDelete, _ := http.NewRequest(http.MethodDelete, "/api/v1/"+rSubmitSignup.User.Id.Hex(), nil)
	reqDelete.Header.Set("Content-Type", "application/json; charset=UTF-8")
	reqDelete.Header.Set("Authorization", "Bearer "+rSubmitSignup.AccessToken)

	// reqDelete.AddCookie(wSubmitSignup.Result().Cookies()[0])

	wDelete := httptest.NewRecorder()
	router.ServeHTTP(wDelete, reqDelete)

	response := &httputil.ResponseSuccess{}
	err = json.Unmarshal(wDelete.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, wDelete.Code, 200)
}

func TestDeleteNotAuthorized(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	managerSecurityKeys.GetAllPublicKeys()

	wSubmitSignup, _ := submitSignup()

	rSubmitSignup := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(wSubmitSignup.Body.Bytes(), rSubmitSignup)
	if err != nil {
		t.Error(err)
	}

	reqDelete, _ := http.NewRequest(http.MethodDelete, "/api/v1/"+rSubmitSignup.User.Id.Hex(), nil)
	reqDelete.Header.Set("Content-Type", "application/json; charset=UTF-8")

	wDelete := httptest.NewRecorder()
	router.ServeHTTP(wDelete, reqDelete)

	response := &httputil.ResponseSuccess{}
	err = json.Unmarshal(wDelete.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, wDelete.Code, 401)
}

func TestDeleteError(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	managerSecurityKeys.GetAllPublicKeys()

	wSubmitSignup, _ := submitSignup()

	rSubmitSignup := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(wSubmitSignup.Body.Bytes(), rSubmitSignup)
	if err != nil {
		t.Error(err)
	}

	reqDelete, _ := http.NewRequest(http.MethodDelete, "/api/v1/ ", nil)
	reqDelete.Header.Set("Content-Type", "application/json; charset=UTF-8")
	reqDelete.Header.Set("Authorization", "Bearer "+rSubmitSignup.AccessToken)

	// reqDelete.AddCookie(wSubmitSignup.Result().Cookies()[0])

	wDelete := httptest.NewRecorder()
	router.ServeHTTP(wDelete, reqDelete)

	response := &httputil.ResponseSuccess{}
	err = json.Unmarshal(wDelete.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, wDelete.Code, 403)
}

func TestRefreshTokenSuccess(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	managerSecurityKeys.GetAllPublicKeys()

	wSubmitSignup, _ := submitSignup()

	rSubmitSignup := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(wSubmitSignup.Body.Bytes(), rSubmitSignup)
	if err != nil {
		t.Error(err)
	}

	refreshTokenDTO := &dtos.RefreshToken{
		RefreshToken: rSubmitSignup.RefreshToken,
	}

	bodyRefreshToken, _ := json.Marshal(refreshTokenDTO)

	reqRefreshToken, _ := http.NewRequest(http.MethodPost, "/api/v1/refresh-token", bytes.NewBuffer(bodyRefreshToken))
	reqRefreshToken.Header.Set("Content-Type", "application/json; charset=UTF-8")

	wRefreshToken := httptest.NewRecorder()
	router.ServeHTTP(wRefreshToken, reqRefreshToken)

	response := &httpresponsecredentials.ResponseCredentials{}
	err = json.Unmarshal(wRefreshToken.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, wRefreshToken.Code, 200)
	assert.NotEqual(t, rSubmitSignup.RefreshToken, response.RefreshToken)
	assert.NotEmpty(t, response.RefreshToken)
}

func TestRefreshTokenInvalid(t *testing.T) {
	// CleanMongoCollection(usersCollection)
	userRepository.ClearCollection()

	managerSecurityKeys.GetAllPublicKeys()

	wSubmitSignup, _ := submitSignup()

	rSubmitSignup := &httpresponsecredentials.ResponseCredentials{}
	err := json.Unmarshal(wSubmitSignup.Body.Bytes(), rSubmitSignup)
	if err != nil {
		t.Error(err)
	}

	refreshTokenDTO := &dtos.RefreshToken{}

	bodyRefreshToken, _ := json.Marshal(refreshTokenDTO)

	reqRefreshToken, _ := http.NewRequest(http.MethodPost, "/api/v1/refresh-token", bytes.NewBuffer(bodyRefreshToken))
	reqRefreshToken.Header.Set("Content-Type", "application/json; charset=UTF-8")

	wRefreshToken := httptest.NewRecorder()
	router.ServeHTTP(wRefreshToken, reqRefreshToken)

	response := &httputil.ResponseError{}
	err = json.Unmarshal(wRefreshToken.Body.Bytes(), response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, wRefreshToken.Code, 400)
	assert.Contains(t, response.Error[0], "invalid refresh token")
}

func TestJWKSSuccess(t *testing.T) {
	// CleanMongoCollection(securityKeysCollection)
	userRepository.ClearCollection()

	managerSecurityKeys.GetAllPublicKeys()

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/jwks", nil)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	response := []*common_models.ECDSAPublicKeysParams{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, w.Code, 200)
	assert.Greater(t, len(response), 0)
}

func TestDownloadPublicKeyJWTSuccess(t *testing.T) {
	//DeleteFolder()
	helpers.CreateFolder(myConfig.Folders)

	managerSecurityKeys.GetAllPublicKeys()

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/download/public-key-jwt", nil)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	response := w.Body.String()

	assert.Equal(t, w.Code, 200)
	assert.NotEmpty(t, response)
}

func TestDownloadCertKeySuccess(t *testing.T) {
	DeleteFolder()
	helpers.CreateFolder(myConfig.Folders)

	_ = managerCertificates.VerifyCertificates()

	hash := base64.StdEncoding.EncodeToString([]byte(myConfig.Certificates.PasswordPermissionEndPoint))
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/download/cert-key/"+hash, nil)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	response := w.Body.String()
	// response := string([]byte(w.Body.Bytes()))

	assert.Equal(t, w.Code, 200)
	assert.NotEmpty(t, response)
}

func TestDownloadCertSuccess(t *testing.T) {
	DeleteFolder()
	helpers.CreateFolder(myConfig.Folders)

	_ = managerCertificates.VerifyCertificates()

	hash := base64.StdEncoding.EncodeToString([]byte(myConfig.Certificates.PasswordPermissionEndPoint))
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/download/cert/"+hash, nil)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	response := w.Body.String()
	// response := string([]byte(w.Body.String()))

	assert.Equal(t, w.Code, 200)
	assert.NotEmpty(t, response)
}

func submitSignup() (*httptest.ResponseRecorder, *dtos.SignUp) {
	signup := &dtos.SignUp{
		Email:           "user1@gmail.com",
		Password:        "123456",
		PasswordConfirm: "123456",
	}

	body, _ := json.Marshal(signup)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/signup", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	return w, signup
}

// func submitSignup() (*httptest.ResponseRecorder, *dtos.SignUp, *http.Cookie) {
// 	signup := &dtos.SignUp{
// 		Email:           "user1@gmail.com",
// 		Password:        "123456",
// 		PasswordConfirm: "123456",
// 	}

// 	body, _ := json.Marshal(signup)

// 	req, _ := http.NewRequest(http.MethodPost, "/api/v1/signup", bytes.NewBuffer(body))
// 	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

// 	w := httptest.NewRecorder()
// 	router.ServeHTTP(w, req)

// 	return w, signup, w.Result().Cookies()[0]
// }
