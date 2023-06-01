package interfaces

type NatsMetric interface {
	SuccessPublishUserDeleted()
	ErrorPublish()
}
