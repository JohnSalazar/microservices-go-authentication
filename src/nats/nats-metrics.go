package nats

import (
	"github.com/oceano-dev/microservices-go-common/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type natsMetric struct {
	config *config.Config
}

var successUserDeleted prometheus.Counter
var errorPublish prometheus.Counter

func NewNatsMetric(
	config *config.Config,
) *natsMetric {
	successUserDeleted = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: config.AppName + "_nats_success_user_deleted_total",
			Help: "The total number of success user deleted NATS messages",
		},
	)

	errorPublish = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: config.AppName + "_nats_error_publish_message_total",
			Help: "The total number of error NATS publish message",
		},
	)

	return &natsMetric{
		config: config,
	}
}

func (nats *natsMetric) SuccessPublishUserDeleted() {
	successUserDeleted.Inc()
}

func (nats *natsMetric) ErrorPublish() {
	errorPublish.Inc()
}
