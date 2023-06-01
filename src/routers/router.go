package routers

import (
	"fmt"

	"authentication/src/controllers"

	"github.com/oceano-dev/microservices-go-common/config"
	"github.com/oceano-dev/microservices-go-common/middlewares"
	common_service "github.com/oceano-dev/microservices-go-common/services"

	"github.com/gin-contrib/location"
	"github.com/gin-gonic/gin"

	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

type Router struct {
	config         *config.Config
	serviceMetrics common_service.Metrics
	authentication *middlewares.Authentication
	authController *controllers.AuthController
}

func NewRouter(
	config *config.Config,
	serviceMetrics common_service.Metrics,
	authentication *middlewares.Authentication,
	authController *controllers.AuthController,
) *Router {
	return &Router{
		config:         config,
		serviceMetrics: serviceMetrics,
		authentication: authentication,
		authController: authController,
	}
}

func (r *Router) RouterSetup() *gin.Engine {
	router := r.initRoute()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(middlewares.CORS())
	router.Use(location.Default())
	router.Use(otelgin.Middleware(r.config.Jaeger.ServiceName))
	router.Use(middlewares.Metrics(r.serviceMetrics))

	router.GET("/healthy", middlewares.Healthy())
	router.GET("/metrics", middlewares.MetricsHandler())

	v1 := router.Group(fmt.Sprintf("/api/%s", r.config.ApiVersion))

	v1.GET("/:email/:page/:size", r.authentication.Verify(),
		middlewares.Authorization("admin", "read"),
		r.authController.GetUsersWithClaim,
	)
	v1.GET("/profile", r.authentication.Verify(),
		// middlewares.Authorization("user", "create,delete,read,update"),
		r.authController.Profile,
	)
	v1.GET("/jwks", r.authController.JWKS)
	v1.GET("/download/public-key-jwt", r.authController.DownloadPublicKeyJWT)
	v1.GET("/download/cacert/:password", r.authController.DownloadCACert)
	v1.GET("/download/cert/:password", r.authController.DownloadCert)
	v1.GET("/download/cert-key/:password", r.authController.DownloadCertKey)

	v1.POST("/signup", r.authController.Signup)
	v1.POST("/user", r.authentication.Verify(),
		middlewares.Authorization("admin", "create"),
		r.authController.CreateUser)
	v1.POST("/signin", r.authController.Signin)
	v1.POST("/request-update-password", r.authController.RequestUpdatePassword)
	v1.POST("/refresh-token", r.authController.RefreshToken)
	v1.POST("/pub/:tipo", r.authController.Pub)

	v1.PUT("/email/:id", r.authentication.Verify(),
		r.authController.UpdateEmail,
	)
	v1.PUT("/password/:email", r.authController.UpdatePassword)
	v1.PUT("/claims/:id", r.authentication.Verify(),
		middlewares.Authorization("admin", "create,update"),
		r.authController.UpdateClaims,
	)

	v1.DELETE("/:id", r.authentication.Verify(),
		r.authController.Delete,
	)

	if !r.config.Production {
		v1.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	}

	return router
}

func (r *Router) initRoute() *gin.Engine {
	if r.config.Production {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	return gin.New()
}
