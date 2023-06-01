package tests

import (
	"context"
	"os"
	"testing"

	"authentication/src/controllers"
	authentication_nats "authentication/src/nats"
	"authentication/src/routers"
	"authentication/src/security"
	jwt "authentication/src/security/jwt"
	"authentication/src/services"
	"authentication/tests/mocks"

	"github.com/gin-gonic/gin"
	"github.com/nats-io/nats.go"
	"github.com/oceano-dev/microservices-go-common/config"
	common_log "github.com/oceano-dev/microservices-go-common/logs"
	"github.com/oceano-dev/microservices-go-common/middlewares"
	common_nats "github.com/oceano-dev/microservices-go-common/nats"
	common_security "github.com/oceano-dev/microservices-go-common/security"
	common_services "github.com/oceano-dev/microservices-go-common/services"
	"github.com/oceano-dev/microservices-go-common/tasks"
	common_validator "github.com/oceano-dev/microservices-go-common/validators"
)

var (
	myConfig                  *config.Config
	authService               *services.AuthenticationService
	securityKeysService       *services.SecurityKeysService
	requestCodeService        *services.RequestCodeService
	certificatesService       services.CertificatesService
	certificatesServiceCommon common_services.CertificatesService
	emailServiceMock          *mocks.EmailServiceMock
	userRepository            *mocks.UserRepositoryMock
	requestCodeRepository     *mocks.RequestCodeRepositoryMock
	securityKeysRepository    *mocks.SecurityKeysRepositoryMock

	managerCertificates common_security.ManagerCertificates
	managerSecurityKeys security.ManagerSecurityKeys
	managerToken        *jwt.ManagerToken
	authController      *controllers.AuthController
	router              *gin.Engine
)

// var usersCollection *mongo.Collection
// var securityKeysCollection *mongo.Collection
// var requestCodesCollection *mongo.Collection

func TestMain(m *testing.M) {
	// mongoServer, err := NewStrikememongo()
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer mongoServer.Stop()

	// setup(mongoServer.URI())
	ctx := context.Background()
	setup(ctx)

	os.Exit(m.Run())
}

// func setup(mongoServerURI string) {
func setup(ctx context.Context) {
	myConfig = config.LoadConfig(false, ".././config/")
	common_validator.NewValidator("en")

	// database := NewClientMongoDatabaseTest(mongoServerURI)

	userRepository = mocks.NewUserRepositoryMock()
	requestCodeRepository = mocks.NewRequestCodeRepositoryMock()
	securityKeysRepository = mocks.NewSecurityKeysRepositoryMock()

	certificatesServiceCommon = common_services.NewCertificatesService(myConfig)
	certificatesService = services.NewCertificatesServices(myConfig, certificatesServiceCommon)
	managerCertificates = security.NewManagerCertificates(myConfig, certificatesService, certificatesServiceCommon)
	emailServiceMock = mocks.NewEmailServiceMock()

	checkCertificates := tasks.NewCheckCertificatesTask(myConfig, managerCertificates, emailServiceMock)
	certsDone := make(chan bool)
	go checkCertificates.Start(ctx, certsDone)
	<-certsDone

	// usersCollection = CreateCollections("users")
	// requestCodesCollection = CreateCollections("requestCodes")
	// securityKeysCollection = CreateCollections("securityKeys")
	// CleanMongoCollection(securityKeysCollection)
	// CleanMongoCollection(usersCollection)
	// CleanMongoCollection(requestCodesCollection)

	authService = services.NewAuthenticationService(userRepository)
	requestCodeService = services.NewRequestCodeService(requestCodeRepository, emailServiceMock)
	securityKeysService = services.NewSecurityKeysService(myConfig, securityKeysRepository)

	managerSecurityKeys = security.NewManagerSecurityKeys(myConfig, securityKeysService)

	managerToken = jwt.NewManagerToken(myConfig, managerSecurityKeys)

	nc, _ := common_nats.NewNats(myConfig, certificatesServiceCommon)
	js, _ := nc.JetStream(nats.PublishAsyncMaxPending(256))
	natsPublisher := common_nats.NewPublisher(js)
	natsMetrics := authentication_nats.NewNatsMetric(myConfig)

	logger := common_log.NewLogger()
	managerTokensCommon := common_security.NewManagerTokens(myConfig, managerSecurityKeys)
	authController = controllers.NewAuthController(
		logger,
		authService,
		requestCodeService,
		managerToken,
		managerTokensCommon,
		managerSecurityKeys,
		myConfig,
		natsPublisher,
		natsMetrics,
		certificatesServiceCommon,
	)
	metricService, _ := common_services.NewMetricsService(myConfig)
	authentication := middlewares.NewAuthentication(logger, managerTokensCommon)
	routers := routers.NewRouter(myConfig, metricService, authentication, authController)
	router = routers.RouterSetup()
}

func DeleteFolder() {
	_ = os.RemoveAll("keys")
	_ = os.RemoveAll("certs")
}
