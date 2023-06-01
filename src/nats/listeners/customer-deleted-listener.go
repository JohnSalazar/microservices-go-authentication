package listeners

import (
	"context"
	"fmt"
	"log"

	"github.com/nats-io/nats.go"
	trace "github.com/oceano-dev/microservices-go-common/trace/otel"
)

type CustomerDeletedListener struct {
}

func NewCustomerDeletedListener() *CustomerDeletedListener {
	return &CustomerDeletedListener{}
}

func (p *CustomerDeletedListener) ProcessCustomerDeleted() nats.MsgHandler {
	return func(msg *nats.Msg) {
		ctx := context.Background()
		_, span := trace.NewSpan(ctx, fmt.Sprintf("publish.%s\n", msg.Subject))
		defer span.End()

		fmt.Println(string(msg.Data))
		fmt.Println("CustomerDeleted processed!!!")

		err := msg.Ack()
		if err != nil {
			log.Printf("nats msg.Ack error: %v", err)
		}
	}
}
