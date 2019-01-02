/*
* Honeytrap
* Copyright (C) 2016-2017 DutchSec (https://dutchsec.com/)
*
* This program is free software; you can redistribute it and/or modify it under
* the terms of the GNU Affero General Public License version 3 as published by the
* Free Software Foundation.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more
* details.
*
* You should have received a copy of the GNU Affero General Public License
* version 3 along with this program in the file "LICENSE".  If not, see
* <http://www.gnu.org/licenses/agpl-3.0.txt>.
*
* See https://honeytrap.io/ for more details. All requests should be sent to
* licensing@honeytrap.io
*
* The interactive user interfaces in modified source and object code versions
* of this program must display Appropriate Legal Notices, as required under
* Section 5 of the GNU Affero General Public License version 3.
*
* In accordance with Section 7(b) of the GNU Affero General Public License version 3,
* these Appropriate Legal Notices must retain the display of the "Powered by
* Honeytrap" logo and retain the original copyright notice. If the display of the
* logo is not reasonably feasible for technical reasons, the Appropriate Legal Notices
* must display the words "Powered by Honeytrap" and retain the original copyright notice.
 */
package server

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/fatih/color"
	"github.com/mattn/go-isatty"

	"github.com/honeytrap/honeytrap/cmd"
	"github.com/honeytrap/honeytrap/config"
	"github.com/honeytrap/honeytrap/config/validator"
	"github.com/honeytrap/honeytrap/web"

	"github.com/honeytrap/honeytrap/director"
	_ "github.com/honeytrap/honeytrap/director/forward"
	_ "github.com/honeytrap/honeytrap/director/lxc"

	// _ "github.com/honeytrap/honeytrap/director/qemu"
	// Import your directors here.

	"github.com/honeytrap/honeytrap/pushers"
	"github.com/honeytrap/honeytrap/pushers/eventbus"

	"github.com/honeytrap/honeytrap/services"
	_ "github.com/honeytrap/honeytrap/services/bannerfmt"
	_ "github.com/honeytrap/honeytrap/services/elasticsearch"
	_ "github.com/honeytrap/honeytrap/services/eos"
	_ "github.com/honeytrap/honeytrap/services/ethereum"
	_ "github.com/honeytrap/honeytrap/services/ftp"
	_ "github.com/honeytrap/honeytrap/services/ipp"
	_ "github.com/honeytrap/honeytrap/services/ldap"
	_ "github.com/honeytrap/honeytrap/services/redis"
	_ "github.com/honeytrap/honeytrap/services/smtp"
	_ "github.com/honeytrap/honeytrap/services/snmp"
	_ "github.com/honeytrap/honeytrap/services/ssh"
	_ "github.com/honeytrap/honeytrap/services/telnet"
	_ "github.com/honeytrap/honeytrap/services/vnc"

	"github.com/honeytrap/honeytrap/listener"
	_ "github.com/honeytrap/honeytrap/listener/agent"
	_ "github.com/honeytrap/honeytrap/listener/canary"
	_ "github.com/honeytrap/honeytrap/listener/netstack"
	_ "github.com/honeytrap/honeytrap/listener/netstack-experimental"
	_ "github.com/honeytrap/honeytrap/listener/socket"
	_ "github.com/honeytrap/honeytrap/listener/tap"
	_ "github.com/honeytrap/honeytrap/listener/tun"

	// proxies

	"github.com/honeytrap/honeytrap/event"
	"github.com/honeytrap/honeytrap/server/profiler"

	_ "github.com/honeytrap/honeytrap/pushers/console"
	_ "github.com/honeytrap/honeytrap/pushers/dshield"
	_ "github.com/honeytrap/honeytrap/pushers/elasticsearch"
	_ "github.com/honeytrap/honeytrap/pushers/file"
	_ "github.com/honeytrap/honeytrap/pushers/kafka"
	_ "github.com/honeytrap/honeytrap/pushers/marija"
	_ "github.com/honeytrap/honeytrap/pushers/pulsar"
	_ "github.com/honeytrap/honeytrap/pushers/rabbitmq"
	_ "github.com/honeytrap/honeytrap/pushers/raven"
	_ "github.com/honeytrap/honeytrap/pushers/slack"
	_ "github.com/honeytrap/honeytrap/pushers/splunk"

	"github.com/op/go-logging"

	// display
	"github.com/honeytrap/honeytrap/minidisplay/buttonhandlers"
	_ "github.com/honeytrap/honeytrap/minidisplay/buttonhandlers/arrowkeyHandler"
	_ "github.com/honeytrap/honeytrap/minidisplay/buttonhandlers/physicalButtonHandler"

	"github.com/honeytrap/honeytrap/minidisplay/displays"
	_ "github.com/honeytrap/honeytrap/minidisplay/displays/lcd"
	_ "github.com/honeytrap/honeytrap/minidisplay/displays/terminal"

	"github.com/honeytrap/honeytrap/minidisplay/node"
	"github.com/honeytrap/honeytrap/minidisplay/userinterface"
)

var log = logging.MustGetLogger("honeytrap/server")

// Honeytrap defines a struct which coordinates the internal logic for the honeytrap
// container infrastructure.
type Honeytrap struct {
	config *config.Config

	profiler profiler.Profiler

	// TODO(nl5887): rename to bus, should we encapsulate this?
	bus *eventbus.EventBus

	director director.Director

	token string

	dataDir string

	// Maps a port and a protocol to an array of pointers to services
	ports     map[net.Addr][]*ServiceMap
	directors map[string]director.Director
	services  map[string]*ServiceMap
	channels  map[string]pushers.Channel

	ui *userinterface.MiniDisplay
}

// New returns a new instance of a Honeytrap struct.
// func New(conf *config.Config) *Honeytrap {
func New(options ...OptionFn) (*Honeytrap, error) {
	bus := eventbus.New()

	// Initialize all channels within the provided config.
	conf := &config.Default

	h := &Honeytrap{
		config:    conf,
		director:  director.MustDummy(),
		bus:       bus,
		profiler:  profiler.Dummy(),
		ports:     make(map[net.Addr][]*ServiceMap),
		services:  make(map[string]*ServiceMap),
		channels:  make(map[string]pushers.Channel),
		directors: map[string]director.Director{},
	}

	for _, fn := range options {
		if err := fn(h); err != nil {
			return nil, err
		}
	}

	return h, nil
}

func (hc *Honeytrap) startAgentServer() {
	// as := proxies.NewAgentServer(hc.director, hc.pusher, hc.configig)
	// go as.ListenAndServe()
}

// EventServiceStarted will return a service started Event struct
func EventServiceStarted(service string) event.Event {
	return event.New(
		event.Category(service),
		event.ServiceSensor,
		event.ServiceStarted,
	)
}

// PrepareRun will prepare Honeytrap to run
func (hc *Honeytrap) PrepareRun() {
}

// Wraps a Servicer, adding some metadata
type ServiceMap struct {
	Service services.Servicer

	Name string
	Type string
}

var (
	ErrNoServicesGivenPort = fmt.Errorf("no services for the given ports")
)

/* Finds a service that can handle the given connection.
 * The service is picked (among those configured for the given port) as follows:
 *
 *     If there are no services for the given port, return an error
 *     If there is only one service, pick it
 *     For each service (as sorted in the config file):
 *         - If it does not implement CanHandle, pick it
 *         - If it implements CanHandle, peek the connection and pass the peeked
 *           data to CanHandle. If it returns true, pick it
 */
func (hc *Honeytrap) findService(conn net.Conn) (*ServiceMap, net.Conn, error) {
	localAddr := conn.LocalAddr()

	var serviceCandidates []*ServiceMap

	for k, sc := range hc.ports {
		if !compareAddr(k, localAddr) {
			continue
		}

		serviceCandidates = sc
	}

	if len(serviceCandidates) == 0 {
		return nil, nil, fmt.Errorf("No service configured for the given port")
	} else if len(serviceCandidates) == 1 {
		return serviceCandidates[0], conn, nil
	}

	peekUninitialized := true
	var tConn net.Conn
	var pConn *peekConnection
	var n int
	buffer := make([]byte, 1024)
	for _, service := range serviceCandidates {
		ch, ok := service.Service.(services.CanHandlerer)
		if !ok {
			// Service does not implement CanHandle, assume it can handle the connection
			return service, conn, nil
		}
		// Service implements CanHandle, initialize it if needed and run the checks
		if peekUninitialized {
			// wrap connection in a connection with deadlines
			tConn = TimeoutConn(conn, time.Second*30)
			pConn = PeekConnection(tConn)
			log.Debug("Peeking connection %s => %s", conn.RemoteAddr(), conn.LocalAddr())
			_n, err := pConn.Peek(buffer)
			n = _n // avoid silly "variable not used" warning
			if err != nil {
				return nil, nil, fmt.Errorf("could not peek bytes: %s", err.Error())
			}
			peekUninitialized = false
		}
		if ch.CanHandle(buffer[:n]) {
			// Service supports payload
			return service, pConn, nil
		}
	}
	// There are some services for that port, but non can handle the connection.
	// Let the caller deal with it.
	return nil, nil, fmt.Errorf("No suitable service for the given port")
}

func (hc *Honeytrap) heartbeat() {
	beat := time.Tick(30 * time.Second)

	count := 0

	for range beat {
		hc.bus.Send(event.New(
			event.Sensor("honeytrap"),
			event.Category("heartbeat"),
			event.SeverityInfo,
			event.Custom("sequence", count),
		))

		count++
	}
}

// Addr, proto, port, error
func ToAddr(input string) (net.Addr, string, int, error) {
	parts := strings.Split(input, "/")

	if len(parts) != 2 {
		return nil, "", 0, fmt.Errorf("wrong format (needs to be \"protocol/(host:)port\")")
	}

	proto := parts[0]

	host, port, err := net.SplitHostPort(parts[1])
	if err != nil {
		port = parts[1]
	}

	portUint16, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, "", 0, fmt.Errorf("error parsing port value: %s", err.Error())
	}

	switch proto {
	case "tcp":
		addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, port))
		return addr, proto, int(portUint16), err
	case "udp":
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
		return addr, proto, int(portUint16), err
	default:
		return nil, "", 0, fmt.Errorf("unknown protocol %s", proto)
	}
}

func IsTerminal(f *os.File) bool {
	if isatty.IsTerminal(f.Fd()) {
		return true
	} else if isatty.IsCygwinTerminal(f.Fd()) {
		return true
	}

	return false
}

func compareAddr(addr1 net.Addr, addr2 net.Addr) bool {
	if ta1, ok := addr1.(*net.TCPAddr); ok {
		ta2, ok := addr2.(*net.TCPAddr)
		if !ok {
			return false
		}

		if ta1.Port != ta2.Port {
			return false
		}

		if ta1.IP == nil {
		} else if ta2.IP == nil {
		} else if !ta1.IP.Equal(ta2.IP) {
			return false
		}

		return true
	} else if ua1, ok := addr1.(*net.UDPAddr); ok {
		ua2, ok := addr2.(*net.UDPAddr)
		if !ok {
			return false
		}

		if ua1.Port != ua2.Port {
			return false
		}

		if ua1.IP == nil {
		} else if ua2.IP == nil {
		} else if !ua1.IP.Equal(ua2.IP) {
			return false
		}

		return true
	}

	return false
}

func (hc *Honeytrap) CreateChannel(key string, channelConfig toml.Primitive) pushers.Channel {
	x := struct {
		Type string `toml:"type"`
	}{}

	if err := hc.config.PrimitiveDecode(channelConfig, &x); err != nil {
		log.Error("Error parsing configuration of channel: %s", err.Error())
		return nil
	}

	channelType := x.Type
	if channelType == "" {
		log.Error("Error parsing configuration of channel %s: type not set", key)
		return nil
	}

	channelFunc, ok := pushers.Get(channelType)
	if !ok {
		log.Error("Channel %s not supported on platform (%s)", channelType, key)
		return nil
	}
	channel, err := channelFunc(
		pushers.WithConfig(channelConfig, hc.config),
	)
	if err != nil {
		log.Fatalf("Error initializing channel %s(%s): %s", key, channelType, err)
		return nil
	}

	return channel
}

func (hc *Honeytrap) CreatePort(s toml.Primitive, l listener.Listener) {

	x := struct {
		Port     string   `toml:"port"`
		Ports    []string `toml:"ports"`
		Services []string `toml:"services"`
	}{}

	if err := hc.config.PrimitiveDecode(s, &x); err != nil {
		log.Error("Error parsing configuration of generic ports: %s", err.Error())
		return
	}

	var ports []string
	if x.Ports != nil {
		ports = x.Ports
	}
	if x.Port != "" {
		ports = append(ports, x.Port)
	}
	if x.Port != "" && x.Ports != nil {
		log.Warning("Both \"port\" and \"ports\" were defined, this can be confusing")
	} else if x.Port == "" && x.Ports == nil {
		log.Error("Neither \"port\" nor \"ports\" were defined")
		return
	}

	if len(x.Services) == 0 {
		log.Warning("No services defined for port(s) " + strings.Join(ports, ", "))
	}

	for _, portStr := range ports {
		addr, _, _, err := ToAddr(portStr)
		if err != nil {
			log.Error("Error parsing port string: %s", err.Error())
			continue
		}
		if addr == nil {
			log.Error("Failed to bind: addr is nil")
			continue
		}

		// Get the services from their names
		var servicePtrs []*ServiceMap
		for _, serviceName := range x.Services {
			ptr, ok := hc.services[serviceName]
			if !ok {
				log.Error("Unknown service '%s' for port %s", serviceName, portStr)
				continue
			}
			servicePtrs = append(servicePtrs, ptr)
		}
		if len(servicePtrs) == 0 {
			log.Errorf("Port %s has no valid services, it won't be listened on", portStr)
			continue
		}

		found := false
		for k, _ := range hc.ports {
			if !compareAddr(k, addr) {
				continue
			}

			found = true
		}

		if found {
			log.Error("Port %s was already defined, ignoring the newer definition", portStr)
			continue
		}

		hc.ports[addr] = servicePtrs

		a, ok := l.(listener.AddAddresser)
		if !ok {
			log.Error("Listener error")
			continue
		}
		a.AddAddress(addr)

		//TODO Pim van Hespen: display this after it is check the port has services
		log.Infof("Configured port %s/%s", addr.Network(), addr.String())
	}

}

func (hc *Honeytrap) CreateService(key string, s toml.Primitive) *ServiceMap {
	x := struct {
		Type     string `toml:"type"`
		Director string `toml:"director"`
		Port     string `toml:"port"`
	}{}

	if err := hc.config.PrimitiveDecode(s, &x); err != nil {
		log.Error("Error parsing configuration of service %s: %s", key, err.Error())
		return nil
	}

	if x.Port != "" {
		log.Error("Ports in services are deprecated, add services to ports instead")
		return nil
	}

	// individual configuration per service
	options := []services.ServicerFunc{
		services.WithChannel(hc.bus),
		services.WithConfig(s, hc.config),
	}

	if x.Director == "" {
	} else if d, ok := hc.directors[x.Director]; ok {
		options = append(options, services.WithDirector(d))
	} else {
		log.Error(color.RedString("Could not find director=%s for service=%s. Enabled directors: %s", x.Director, key, strings.Join(director.GetAvailableDirectorNames(), ", ")))
		return nil
	}

	fn, ok := services.Get(x.Type)
	if !ok {
		log.Error(color.RedString("Could not find type %s for service %s", x.Type, key))
		return nil
	}

	service := fn(options...)
	return &ServiceMap{
		Service: service,
		Name:    key,
		Type:    x.Type,
	}
}

func (hc *Honeytrap) CreateMiniDisplay() {
	encodedScreen := hc.config.MiniDisplay["screen"]
	tomlButton := hc.config.MiniDisplay["button"]

	typeStruct := struct {
		Type string `toml:"type"`
	}{}

	buttonType, screenType := typeStruct, typeStruct //copy

	//try to decode it
	if err := hc.config.PrimitiveDecode(encodedScreen, &screenType); err != nil {
		log.Error("Error parsing configuration of screen: %s", err.Error())
		return
	}

	if err := hc.config.PrimitiveDecode(tomlButton, &buttonType); err != nil {
		log.Error("Error parsing configuration of buttons, %s", err.Error())
		return
	}

	// try to get the tyoe
	if screenType.Type == "" {
		log.Error("Error parsing configuration for screen. No screentype declared")
		return
	}
	if buttonType.Type == "" {
		log.Error("Error parsing configuration for buttons. No buttontype declared")
		return
	}

	// try to create a display
	var screen displays.Display
	if fn, ok := displays.Get(screenType.Type); !ok {
		log.Errorf("Error parsing configuration for screen. Unknown screen type: %s", screenType.Type)
		return
	} else if candidate, err := fn(encodedScreen, hc.config); err != nil {
		log.Errorf("Error parsing configuration for screen. \n%s", err.Error())
		return
	} else {
		screen = candidate
	}

	// try to create a buttonhandler
	var buttonhandler buttonhandlers.ButtonHandler
	if fn, ok := buttonhandlers.Get(buttonType.Type); !ok {
		log.Errorf("Error parsing configuration for buttons. Unknown button type: %s", buttonType.Type)
		return
	} else if candidate, err := fn(tomlButton, hc.config); err != nil {
		log.Errorf("Error parsing configuration for buttons. \n%s", err.Error())
		return
	} else {
		candidate.Start()
		buttonhandler = candidate
	}

	root := &node.Root{
		Name: "Honeytrap",
	}

	tokenData := &node.Data{
		Name:    "Token",
		Parent:  root,
		DataSrc: &node.MockDataSource{hc.token},
		Width:   screen.Width(),
	}
	root.Children = append(root.Children, tokenData)

	//services
	servicesNode := &node.Link{
		Name:   "Services",
		Parent: root,
	}
	root.Children = append(root.Children, servicesNode)

	// should be dervied from the config manager
	// ie
	/*for _, servicemap := range hc.configManager.Services() {
		// do nothing... for now
		fmt.Println(servicemap)
	}*/
	for port, servicemaps := range hc.ports {
		for _, servicemap := range servicemaps {
			n := &node.Link{
				Name: (servicemap).Name,
				//Parent: servicesNode,
			}
			servicesNode.AddChild(n)

			split := strings.Split(port.String(), ":")
			portnr := split[len(split)-1]
			portstring := fmt.Sprintf("%s/%s", port.Network(), portnr)

			dataChild := &node.Data{
				Name: "Port",
				//Parent:  n,
				DataSrc: &node.MockDataSource{portstring},
				Width:   screen.Width(),
			}
			n.AddChild(dataChild)

			action := &node.Action{
				Name: "Disable Service",
				//Parent: n,
			}
			n.AddChild(action)

			action.Action = &node.ExecuteActionType{
				Execute: func() {
					//TODO ugly. To be fixed later
					if action.Name == "Disable Service" {
						action.Name = "Enable Service"
					} else {
						action.Name = "Disable Service"
					}
					hc.bus.Send(event.New(
						event.Sensor("honeytrap"),
						event.Category("configuration"),
						event.Service((servicemap).Type),
						//TODO: Switch To Specific :ENABLE / :DISABLE
						event.Type("SERVICE:TOGGLE"),
					))
				},
			}
		}
	}
	//TODO: make this an issue on repo
	resp, err := http.Get("https://api.ipify.org")

	ipaddr := "Error: could not find IP"

	if err == nil {
		content, err := ioutil.ReadAll(resp.Body)
		if err == nil {
			ipaddr = string(content[0:])
		}
		resp.Body.Close()
	}

	ipaddrData := &node.Data{
		Name:    "External IP",
		Parent:  root,
		DataSrc: &node.MockDataSource{ipaddr},
		Width:   screen.Width(),
	}
	root.Children = append(root.Children, ipaddrData)

	// init ui
	hc.ui = userinterface.New(screen, buttonhandler, root)

	go func() {
		userinterface.WelcomeScreenBee(hc.ui.Display)
		time.Sleep(1 * time.Second)
		hc.ui.Refresh()
	}()
}

// Run will start honeytrap
func (hc *Honeytrap) Run(ctx context.Context) {
	if IsTerminal(os.Stdout) {
		fmt.Println(color.YellowString(`
 _   _                       _____                %c
| | | | ___  _ __   ___ _   |_   _| __ __ _ _ __
| |_| |/ _ \| '_ \ / _ \ | | || || '__/ _' | '_ \
|  _  | (_) | | | |  __/ |_| || || | | (_| | |_) |
|_| |_|\___/|_| |_|\___|\__, ||_||_|  \__,_| .__/
                        |___/              |_|
`, 127855))
	}

	fmt.Println(color.YellowString("Honeytrap starting (%s)...", hc.token))
	fmt.Println(color.YellowString("Version: %s (%s)", cmd.Version, cmd.ShortCommitID))

	log.Debugf("Using datadir: %s", hc.dataDir)

	go hc.heartbeat()

	hc.profiler.Start()

	hc.config = validator.Validate(hc.config)

	w, err := web.New(
		web.WithEventBus(hc.bus),
		web.WithDataDir(hc.dataDir),
		web.WithConfig(hc.config.Web, hc.config),
	)
	if err != nil {
		log.Error("Error parsing configuration of web: %s", err.Error())
	}

	w.Start()

	// subscribe default to global bus
	// maybe we can rewrite pushers / channels to use global bus instead
	bc := pushers.NewBusChannel()
	hc.bus.Subscribe(bc)

	//TODO pimvanhespen: get this map out of here
	isChannelUsed := make(map[string]bool)

	// sane defaults!

	//create channels
	for key, channelConfig := range hc.config.Channels {

		channel := hc.CreateChannel(key, channelConfig)
		if channel == nil {
			continue
		}

		hc.channels[key] = channel
		isChannelUsed[key] = false

	}

	// create filters
	for _, s := range hc.config.Filters {

		x := struct {
			Channels   []string `toml:"channel"`
			Services   []string `toml:"services"`
			Categories []string `toml:"categories"`
		}{}

		err := hc.config.PrimitiveDecode(s, &x)
		if err != nil {
			log.Error("Error parsing configuration of filter: %s", err.Error())
			continue
		}

		for _, name := range x.Channels {
			channel, ok := hc.channels[name]
			if !ok {
				log.Error("Could not find channel %s for filter", name)
				continue
			}

			isChannelUsed[name] = true
			channel = pushers.TokenChannel(channel, hc.token)

			if len(x.Categories) != 0 {
				channel = pushers.FilterChannel(channel, pushers.RegexFilterFunc("category", x.Categories))
			}

			if len(x.Services) != 0 {
				channel = pushers.FilterChannel(channel, pushers.RegexFilterFunc("service", x.Services))
			}

			if err := hc.bus.Subscribe(channel); err != nil {
				log.Error("Could not add channel %s to bus: %s", name, err.Error())
			}
		}
	}

	// check if all channels are in use
	for name, isUsed := range isChannelUsed {
		if !isUsed {
			log.Warningf("Channel %s is unused. Did you forget to add a filter?", name)
		}
	}

	// initialize directors

	// variable only used for error.
	availableDirectorNames := director.GetAvailableDirectorNames()

	for key, s := range hc.config.Directors {
		x := struct {
			Type string `toml:"type"`
		}{}

		err := hc.config.PrimitiveDecode(s, &x)
		if err != nil {
			log.Error("Error parsing configuration of director: %s", err.Error())
			continue
		}

		if x.Type == "" {
			log.Error("Error parsing configuration of service %s: type not set", key)
			continue
		}

		if directorFunc, ok := director.Get(x.Type); !ok {
			log.Error("Director type=%s not supported on platform (director=%s). Available directors: %s", x.Type, key, strings.Join(availableDirectorNames, ", "))
		} else if d, err := directorFunc(
			director.WithChannel(hc.bus),
			director.WithConfig(s, hc.config),
		); err != nil {
			log.Fatalf("Error initializing director %s(%s): %s", key, x.Type, err)
		} else {
			hc.directors[key] = d
		}
	}

	var enabledDirectorNames []string
	for key := range hc.directors {
		enabledDirectorNames = append(enabledDirectorNames, key)
	}

	// same for services
	for key, s := range hc.config.Services {
		service := hc.CreateService(key, s)
		if service == nil {
			continue
		}
		hc.services[key] = service
		log.Infof("Configured service (%s)", key) // x.Type removed
	}

	// initialize listener
	x := struct {
		Type string `toml:"type"`
	}{}

	if err := hc.config.PrimitiveDecode(hc.config.Listener, &x); err != nil {
		log.Error("Error parsing configuration of listener: %s", err.Error())
		return
	}

	if x.Type == "" {
		fmt.Println(color.RedString("Listener not set"))
	}

	listenerFunc, ok := listener.Get(x.Type)
	if !ok {
		fmt.Println(color.RedString("Listener %s not support on platform", x.Type))
		return
	}

	l, err := listenerFunc(
		listener.WithChannel(hc.bus),
		listener.WithConfig(hc.config.Listener, hc.config),
	)
	if err != nil {
		log.Fatalf("Error initializing listener %s: %s", x.Type, err)
	}

	// init ports
	for _, s := range hc.config.Ports {
		hc.CreatePort(s, l)
	}

	//check if all services are assigned to ports
	knownServicePointers := []*ServiceMap{}
	for _, serviceMaps := range hc.ports {
		knownServicePointers = append(knownServicePointers, serviceMaps...)
	}

	for serviceName, serviceMapPointer := range hc.services {
		// check if service is listed in the services mapped to ports
		if !func() bool {
			for _, pointer := range knownServicePointers {
				if pointer == serviceMapPointer {
					return true
				}
			}
			return false
		}() {
			log.Warningf("Service %s is defined but not used", serviceName)
		}
	}

	// config of mini diplay
	if len(hc.config.MiniDisplay) == 0 {
		log.Info("Starting without MiniDisplay")
	} else {
		log.Info("Starting with Minidisplay")
		hc.CreateMiniDisplay()
	}

	if len(hc.config.Undecoded()) != 0 {
		log.Warningf("Unrecognized keys in configuration: %v", hc.config.Undecoded())
	}

	if err := l.Start(ctx); err != nil {
		fmt.Println(color.RedString("Error starting listener: %s", err.Error()))
		return
	}

	incoming := make(chan net.Conn)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				panic(err)
			}

			incoming <- conn

			// in case of goroutine starvation
			// with many connection and single procs
			runtime.Gosched()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case conn := <-incoming:
			go hc.handle(conn)
		}
	}
}

func (hc *Honeytrap) handle(conn net.Conn) {
	defer func() {
		if err := recover(); err != nil {
			trace := make([]byte, 1024)
			count := runtime.Stack(trace, true)
			log.Errorf("Error: %s", err)
			log.Errorf("Stack of %d bytes: %s\n", count, string(trace))
			return
		}
	}()

	defer conn.Close()

	defer func() {
		if r := recover(); r != nil {
			message := event.Message("%+v", r)
			if err, ok := r.(error); ok {
				message = event.Message("%+v", err)
			}

			hc.bus.Send(event.New(
				event.SeverityFatal,
				event.SourceAddr(conn.RemoteAddr()),
				event.DestinationAddr(conn.LocalAddr()),
				event.Stack(),
				message,
			))
		}
	}()

	log.Debug("Accepted connection for %s => %s", conn.RemoteAddr(), conn.LocalAddr())
	defer log.Debug("Disconnected connection for %s => %s", conn.RemoteAddr(), conn.LocalAddr())

	/* conn is the original connection. newConn can be either the same
	 * connection, or a wrapper in the form of a PeekConnection.
	 */
	sm, newConn, err := hc.findService(conn)
	if sm == nil {
		log.Debug("No suitable handler for %s => %s: %s", conn.RemoteAddr(), conn.LocalAddr(), err.Error())
		return
	}

	log.Debug("Handling connection for %s => %s %s(%s)", conn.RemoteAddr(), conn.LocalAddr(), sm.Name, sm.Type)

	newConn = TimeoutConn(newConn, time.Second*30)

	ctx := context.Background()
	if err := sm.Service.Handle(ctx, newConn); err != nil {
		log.Errorf(color.RedString("Error handling service: %s: %s", sm.Name, err.Error()))
	}
}

// Stop will stop Honeytrap
func (hc *Honeytrap) Stop() {
	hc.profiler.Stop()
	if hc.ui != nil {
		hc.ui.Close()
	}
	fmt.Println(color.YellowString("Honeytrap stopped."))
}
