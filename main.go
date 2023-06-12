package main

import (
	"authentication/src/controllers"
	authentication_nats "authentication/src/nats"
	"encoding/json"
	"fmt"

	common_grpc_client "github.com/JohnSalazar/microservices-go-common/grpc/email/client"
	"github.com/JohnSalazar/microservices-go-common/httputil"
	"github.com/JohnSalazar/microservices-go-common/middlewares"

	"github.com/JohnSalazar/microservices-go-common/helpers"
	common_log "github.com/JohnSalazar/microservices-go-common/logs"
	common_nats "github.com/JohnSalazar/microservices-go-common/nats"
	provider "github.com/JohnSalazar/microservices-go-common/trace/otel/jaeger"
	"golang.org/x/crypto/bcrypt"

	"github.com/JohnSalazar/microservices-go-common/config"
	common_repositories "github.com/JohnSalazar/microservices-go-common/repositories"
	common_security "github.com/JohnSalazar/microservices-go-common/security"
	common_services "github.com/JohnSalazar/microservices-go-common/services"
	common_tasks "github.com/JohnSalazar/microservices-go-common/tasks"

	"authentication/src/repositories"
	"authentication/src/routers"
	"authentication/src/security"
	jwt "authentication/src/security/jwt"
	"authentication/src/services"
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"go.mongodb.org/mongo-driver/mongo"

	_ "authentication/docs"

	common_consul "github.com/JohnSalazar/microservices-go-common/consul"
	common_validator "github.com/JohnSalazar/microservices-go-common/validators"
	consul "github.com/hashicorp/consul/api"
)

// var emailService *common_grpc_client.EmailServiceClientGrpc

type Main struct {
	config              *config.Config
	client              *mongo.Client
	natsConn            *nats.Conn
	managerSecurityKeys security.ManagerSecurityKeys
	adminMongoDbService *common_services.AdminMongoDbService
	requestCodeService  *services.RequestCodeService
	httpServer          httputil.HttpServer
	consulClient        *consul.Client
	serviceID           string
}

func NewMain(
	config *config.Config,
	client *mongo.Client,
	natsConn *nats.Conn,
	managerSecurityKeys security.ManagerSecurityKeys,
	adminMongoDbService *common_services.AdminMongoDbService,
	requestCodeService *services.RequestCodeService,
	httpServer httputil.HttpServer,
	consulClient *consul.Client,
	serviceID string,
) *Main {
	return &Main{
		config:              config,
		client:              client,
		natsConn:            natsConn,
		managerSecurityKeys: managerSecurityKeys,
		adminMongoDbService: adminMongoDbService,
		requestCodeService:  requestCodeService,
		httpServer:          httpServer,
		consulClient:        consulClient,
		serviceID:           serviceID,
	}
}

// @title           Microservices Go
// @version         1.0
// @description     This is a authentication server.
// @termsOfService  http://swagger.io/terms/

// @contact.name   API Support
// @contact.url    http://www.microservices.go/support
// @contact.email  support@microservices.go

// @license.name  Apache 2.0
// @license.url   http://www.apache.org/licenses/LICENSE-2.0.html

// @BasePath  /api/v1
// @Schemes  https

//	@securityDefinitions.apikey	Bearer
//	@in							header
//	@name						Authorization
//	@description		Type "Bearer" followed by a space and JWT token.

var production *bool
var disableTrace *bool

func main() {
	production = flag.Bool("prod", false, "use -prod=true to run in production mode")
	disableTrace = flag.Bool("disable-trace", false, "use disable-trace=true if you want to disable tracing completly")

	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	app, err := startup(ctx)
	if err != nil {
		panic(err)
	}

	if app.config.Certificates.HashPermissionEndPoint == "" || app.config.Certificates.PasswordPermissionEndPoint == "" {
		generateHashPermissionEndPoint(app, *production)
	}

	providerTracer, err := provider.NewProvider(provider.ProviderConfig{
		JaegerEndpoint: app.config.Jaeger.JaegerEndpoint,
		ServiceName:    app.config.Jaeger.ServiceName,
		ServiceVersion: app.config.Jaeger.ServiceVersion,
		Production:     *production,
		Disabled:       *disableTrace,
	})
	if err != nil {
		log.Fatalln(err)
	}
	defer providerTracer.Close(ctx)
	log.Println("Connected to Jaegger")

	err = app.client.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer app.client.Disconnect(ctx)

	err = app.client.Ping(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Connected to MongoDB")

	defer app.natsConn.Close()

	app.managerSecurityKeys.GetAllPrivateKeys()

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	userMongoExporter, err := app.adminMongoDbService.VerifyMongoDBExporterUser()
	if err != nil {
		log.Fatal(err)
	}

	if !userMongoExporter {
		log.Fatal("MongoDB Exporter user not found!")
	}

	app.httpServer.RunTLSServer()

	// var email *common_services.EmailServiceClientGrpc
	// err = emailService.SendPasswordCode("joaobosco.salazar@gmail.com", "1234")
	// if err != nil {
	// 	fmt.Println(err)
	// }

	// err = email.SendSupportMessage(grpcClient, "error test")
	// if err != nil {
	// 	fmt.Println(err)
	// }

	<-done
	log.Println("serviceID: ", app.serviceID)
	err = app.consulClient.Agent().ServiceDeregister(app.serviceID)
	if err != nil {
		log.Printf("consul deregister error: %s", err)
	}

	log.Print("Server Stopped")
	os.Exit(0)

	// _, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	// defer func() {
	// 	// extra handling here
	// 	cancel()
	// }()
	// log.Println("Server exiting")
}

func startup(ctx context.Context) (*Main, error) {
	logger := common_log.NewLogger()
	config := config.LoadConfig(*production, "./config/")
	helpers.CreateFolder(config.Folders)
	common_validator.NewValidator("en")

	consulClient, serviceID, err := common_consul.NewConsulClient(config)
	if err != nil {
		log.Fatal(err.Error())
	}

	checkServiceName := common_tasks.NewCheckServiceNameTask()

	emailsServiceNameDone := make(chan bool)
	go checkServiceName.ReloadServiceName(
		ctx,
		config,
		consulClient,
		config.EmailService.ServiceName,
		common_consul.EmailService,
		emailsServiceNameDone)
	<-emailsServiceNameDone

	metricService, err := common_services.NewMetricsService(config)
	if err != nil {
		log.Fatal(err.Error())
	}

	client, err := repositories.NewMongoClient(config)
	if err != nil {
		return nil, err
	}

	certificatesServiceCommon := common_services.NewCertificatesService(config)
	certificatesService := services.NewCertificatesServices(config, certificatesServiceCommon)
	managerCertificates := security.NewManagerCertificates(config, certificatesService, certificatesServiceCommon)
	emailService := common_grpc_client.NewEmailServiceClientGrpc(config, certificatesServiceCommon)

	checkCertificates := common_tasks.NewCheckCertificatesTask(config, managerCertificates, emailService)
	certsDone := make(chan bool)
	go checkCertificates.Start(ctx, certsDone)
	<-certsDone

	nc, err := common_nats.NewNats(config, certificatesServiceCommon)
	if err != nil {
		log.Fatalf("Nats connect error: %+v", err)
	}
	log.Printf("Nats Connected Status: %+v	", nc.Status().String())

	subjects := []string{string(common_nats.CustomerDeleted)}
	js, err := common_nats.NewJetStream(nc, "customer", subjects)
	if err != nil {
		log.Fatalf("Nats JetStream create error: %+v", err)
	}

	natsPublisher := common_nats.NewPublisher(js)
	listens := authentication_nats.NewListen(js)
	listens.Listen()
	natsMetrics := authentication_nats.NewNatsMetric(config)

	database := repositories.NewMongoDatabase(config, client)
	adminMongoDbRepository := common_repositories.NewAdminMongoDbRepository(database)
	adminMongoDbService := common_services.NewAdminMongoDbService(config, adminMongoDbRepository)
	userRepository := repositories.NewUserRepository(database)
	authService := services.NewAuthenticationService(userRepository)
	securityKeysRepository := repositories.NewSecurityKeysRepository(database)
	securityKeysService := services.NewSecurityKeysService(config, securityKeysRepository)
	managerSecurityKeys := security.NewManagerSecurityKeys(config, securityKeysService)

	managerToken := jwt.NewManagerToken(config, managerSecurityKeys)
	managerTokensCommon := common_security.NewManagerTokens(config, managerSecurityKeys)

	requestCodeRepository := repositories.NewRequestCodeRepository(database)
	requestCodeService := services.NewRequestCodeService(requestCodeRepository, emailService)

	authentication := middlewares.NewAuthentication(logger, managerTokensCommon)

	authController := controllers.NewAuthController(
		logger,
		authService,
		requestCodeService,
		managerToken,
		managerTokensCommon,
		managerSecurityKeys,
		config,
		natsPublisher,
		natsMetrics,
		certificatesServiceCommon,
	)
	router := routers.NewRouter(config, metricService, authentication, authController)
	httpserver := httputil.NewHttpServer(config, router.RouterSetup(), certificatesServiceCommon)
	app := NewMain(
		config,
		client,
		nc,
		managerSecurityKeys,
		adminMongoDbService,
		requestCodeService,
		httpserver,
		consulClient,
		serviceID,
	)

	return app, nil
}

func generateHashPermissionEndPoint(app *Main, prod bool) {
	var passwordPermissionEndPoint string
	if app.config.Certificates.PasswordPermissionEndPoint == "" {
		passwordPermissionEndPoint = helpers.GenerateRandomString(20)
	}

	fmt.Println(passwordPermissionEndPoint)

	hash, err := bcrypt.GenerateFromPassword([]byte(passwordPermissionEndPoint), bcrypt.MinCost)
	if err != nil {
		log.Fatalf("generateHashPermissionEndPoint error: %s", err)
	}

	fmt.Println(hash)

	createHashAndPasswordPermissionEndPointCertificate(prod, string(hash), passwordPermissionEndPoint)
}

func createHashAndPasswordPermissionEndPointCertificate(prod bool, hash string, password string) {
	fileName := "src/config/config-dev.json"
	if prod {
		fileName = "src/config/config-prod.json"
	}

	file, _ := os.ReadFile(fileName)

	var byteValue map[string]interface{}
	json.Unmarshal(file, &byteValue)

	for k := range byteValue {
		if k == "certificates" {
			resultMap := byteValue[k].(map[string]interface{})
			resultMap["hashPermissionEndPoint"] = hash
			resultMap["passwordPermissionEndPoint"] = password
		}
	}

	jsonString, _ := json.MarshalIndent(byteValue, "", " ")
	os.WriteFile(fileName, jsonString, os.ModePerm)
}
