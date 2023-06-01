package nats

import (
	"authentication/src/nats/listeners"
	"log"

	"github.com/nats-io/nats.go"
	common_nats "github.com/oceano-dev/microservices-go-common/nats"
)

type listen struct {
	js nats.JetStreamContext
}

const queueGroupName string = "authentications-service"

var subscribe common_nats.Listener
var customerDelete *listeners.CustomerDeletedListener

func NewListen(
	js nats.JetStreamContext,
) *listen {
	subscribe = common_nats.NewListener(js)
	return &listen{
		js: js,
	}
}

func (l *listen) Listen() {
	go subscribe.Listener(string(common_nats.CustomerDeleted), queueGroupName, queueGroupName+"_0", customerDelete.ProcessCustomerDeleted())

	log.Printf("Listener on!!!")
}
