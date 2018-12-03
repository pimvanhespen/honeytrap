package configuration

import (
	"github.com/honeytrap/honeytrap/event"
	"github.com/honeytrap/honeytrap/pushers"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("channels/configuration")

type Configuration struct {
	ch chan event.Event
}

func New(options ...func(pushers.Channel) error) (pushers.Channel, error) {
	ch := make(chan event.Event, 100)

	c := Configuration{
		ch: ch,
	}

	for _, optionFn := range options {
		optionFn(&c)
	}

	go c.Run()

	return &c, nil
}

func (c Configuration) Run() {
	for {
		select {
		case evt := <-c.ch:
			category := evt.Get("category")
			// ignore events that aren't related to configuring the honeytrap
			if category != "configuration" {
				continue
			}
			service := evt.Get("service")
			evtType := evt.Get("type")

			log.Infof("%s, %s, %s", category, service, evtType)
		}
	}
}

func (c Configuration) Send(message event.Event) {
	select {
	case c.ch <- message:
	default:
		log.Errorf("Could not send more messages, channel full")
	}
}
