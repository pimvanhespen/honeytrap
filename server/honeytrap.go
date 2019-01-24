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
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
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

	State

	stats map[string]int

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

	listnr listener.Listener

	//TODO define somewhere else. Keep for now
	svNode *node.Link
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
		stats:     map[string]int{},
	}

	h.stats["received"] = 0
	h.stats["handled"] = 0

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

func (hc *Honeytrap) CreateChannel(name, typ string, channelConfig toml.Primitive) error {
	channelFunc, ok := pushers.Get(typ)
	if !ok {
		return fmt.Errorf("Failed to create channel %s", typ)
	}
	channel, err := channelFunc(
		pushers.WithConfig(channelConfig, hc.config),
	)
	if err != nil {
		return fmt.Errorf("Error initializing channel %s(%s): %s", name, typ, err)
	}

	hc.channels[name] = channel
	log.Infof("Configured channel %s(%s)", name, typ)
	return nil
}
func (hc *Honeytrap) CreateFilter(target string, cats, svcs []string, conf toml.Primitive) error {
	channel, ok := hc.channels[target]
	if !ok {
		return fmt.Errorf("Could not find channel %s for filter", target)
	}

	channel = pushers.TokenChannel(channel, hc.token)

	if len(cats) != 0 {
		channel = pushers.FilterChannel(channel, pushers.RegexFilterFunc("category", cats))
	}

	if len(svcs) != 0 {
		channel = pushers.FilterChannel(channel, pushers.RegexFilterFunc("service", svcs))
	}

	if err := hc.bus.Subscribe(channel); err != nil {
		return fmt.Errorf("Could not add channel %s to bus: %s", target, err.Error())
	}

	log.Infof("Added filter (from channel: %s) to bus", target)
	return nil
}
func (hc *Honeytrap) CreateDirector(tp, key string, conf toml.Primitive) error {
	directorFunc, _ := director.Get(tp)
	d, err := directorFunc(
		director.WithChannel(hc.bus),
		director.WithConfig(conf, hc.config),
	)
	if err != nil {
		return fmt.Errorf("Error initializing director %s(%s): %s", key, tp, err)
	}
	hc.directors[key] = d
	return nil
}
func (hc *Honeytrap) CreateService(key, serviceType, dir string, s toml.Primitive) error {
	// individual configuration per service
	options := []services.ServicerFunc{
		services.WithChannel(hc.bus),
		services.WithConfig(s, hc.config),
	}

	if dir == "" {
	} else if d, ok := hc.directors[dir]; ok {
		options = append(options, services.WithDirector(d))
	} else {
		return fmt.Errorf(color.RedString("Could not find director=%s for service=%s. Enabled directors: %s", dir, key, strings.Join(director.GetAvailableDirectorNames(), ", ")))
	}

	fn, ok := services.Get(serviceType)
	if !ok {
		return fmt.Errorf(color.RedString("Could not find type %s for service %s", serviceType, key))
	}

	service := fn(options...)
	hc.services[key] = &ServiceMap{
		Service: service,
		Name:    key,
		Type:    serviceType,
	}
	log.Infof("Configured service (%s)", key) // x.Type removed
	return nil
}
func (hc *Honeytrap) CreatePort(ports []net.Addr, services []string) error {
	servicePtrs := []*ServiceMap{}

	for _, serviceName := range services {
		ptr, ok := hc.services[serviceName]
		//NOTE: implemented!
		if !ok {
			return fmt.Errorf("Unknown service '%s' for port %v", serviceName, ports)
		}
		servicePtrs = append(servicePtrs, ptr)
	}

	for _, portAddr := range ports {

		hc.ports[portAddr] = servicePtrs

		a, ok := hc.listnr.(listener.AddAddresser)
		if !ok {
			return fmt.Errorf("Listener error")
		}
		a.AddAddress(portAddr)

		log.Infof("Configured port %s/%s", portAddr.Network(), portAddr.String())
	}

	return nil // execution succes, no errors!
}

//TODO REMOVE THIS< CHANGE IT< WHAT EVER. IT SHOULDNT BE HERE!
func (hc *Honeytrap) PopulateServicesNode() {
	fmt.Println(hc.svNode)
	fmt.Println(*hc.svNode)

	servicesNode := hc.svNode
	if servicesNode == nil {
		panic("NIL@@@")
	}
	//TODO change this, children are not unlinked.
	for _, x := range servicesNode.Children {
		x.SetParent(nil)
	}
	servicesNode.Children = []node.Node{}
	//	fmt.Println(*servicesNode)
	//	fmt.Println(hc.ports)
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
				Width:   16, //TODO fix this!
			}
			n.AddChild(dataChild)

			/*
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
				}*/
		}
	}
}

func (hc *Honeytrap) CreateMiniDisplay() {
	encodedScreen := hc.config.MiniDisplay["screen"]
	tomlButton := hc.config.MiniDisplay["button"]

	//fmt.Println("dsiplay config:\t", hc.config.MiniDisplay)

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
	root.AddChild(tokenData)

	//services
	servicesNode := &node.Link{
		Name:   "Services",
		Parent: root,
	}
	root.AddChild(servicesNode)

	// should be dervied from the config manager
	// ie
	//for _, servicemap := range hc.configManager.Services() {
	//	// do nothing... for now
	//	fmt.Println(servicemap)
	//}

	hc.svNode = servicesNode

	hc.PopulateServicesNode()

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
	root.AddChild(ipaddrData)

	// init ui
	hc.ui = userinterface.New(screen, buttonhandler, root)

	profileSelection := &node.Link{
		Name: "Select Profile",
	}

	for i := 1; i <= 2; i++ {
		profile := &node.Action{
			Name: fmt.Sprintf("Profile %v", i),
			Action: &node.ExecuteActionType{
				Execute: func() {
					hc.bus.Send(event.New(
						event.Sensor("honeytrap"),
						event.Category("configuration"),
						event.Type("HONEYTRAP:OVERWRITE"),
						event.Custom("file", fmt.Sprintf("./config-profile-%v.toml", i)),
					))
				},
			},
		}
		profileSelection.AddChild(profile)
	}
	root.AddChild(profileSelection)

	go func() {
		userinterface.WelcomeScreenBee(hc.ui.Display)
		time.Sleep(1 * time.Second)
		hc.ui.Refresh()
	}()
}

type ConfigManager struct {
	*Honeytrap
	*validator.Validata
	start chan chan chan struct{}
	*logging.Logger
}

var configlogger = logging.MustGetLogger("honeytrap/config/manager")

func NewConfigManager(subject *Honeytrap) *ConfigManager {
	manager := &ConfigManager{
		Honeytrap: subject,
		start:     make(chan chan chan struct{}, 1), //TODO remove the channelception
		Logger:    configlogger,
	}
	return manager
}

type ConfigFunc func(*Honeytrap) error

func createChannel(c validator.Channel) ConfigFunc {
	return func(h *Honeytrap) error {
		return h.CreateChannel(c.Name, c.Type, c.Primitive)
	}
}
func removeChannel(c validator.Channel) ConfigFunc {
	return func(h *Honeytrap) error {
		return fmt.Errorf("removeChannel not implemented")
	}
}
func channelActions(specs []validator.Channel) (add, remove []ConfigFunc) {
	for _, channel := range specs {
		switch channel.Action {
		case validator.IGNORE, validator.KEEP:
			// do nothing
		case validator.DISCARD:
			remove = append(remove, removeChannel(channel))
		case validator.CREATE:
			add = append(add, createChannel(channel))
		default:
			configlogger.Error("Error while building change spec: Unknown action type: %v", channel.Action)
		}
	}
	return
}

func createFilter(filter validator.Filter) ConfigFunc {
	return func(h *Honeytrap) error {
		return h.CreateFilter(filter.Target, filter.Categories, filter.Services, filter.Primitive)
	}
}
func removeFilter(fiter validator.Filter) ConfigFunc {
	return func(h *Honeytrap) error {
		return fmt.Errorf("remove filter not implemented")
	}
}
func filterActions(specs []validator.Filter) (add, remove []ConfigFunc) {
	for _, filter := range specs {
		switch filter.Action {
		case validator.IGNORE, validator.KEEP:
			// do nothing
		case validator.DISCARD:
			remove = append(remove, removeFilter(filter))
		case validator.CREATE:
			add = append(add, createFilter(filter))
		default:
			configlogger.Error("Error while building change spec: Unknown action type: %v", filter.Action)
		}
	}
	return
}

func createDirector(d validator.Director) ConfigFunc {
	return func(h *Honeytrap) error {
		return h.CreateDirector(d.Type, d.Name, d.Primitive)
	}
}
func removeDirector(d validator.Director) ConfigFunc {
	return func(h *Honeytrap) error {
		return fmt.Errorf("removeDirector not implemented")
	}
}
func directorActions(specs []validator.Director) (add, remove []ConfigFunc) {
	for _, d := range specs {
		switch d.Action {
		case validator.IGNORE, validator.KEEP:
			// do nothing
		case validator.DISCARD:
			remove = append(remove, removeDirector(d))
		case validator.CREATE:
			add = append(add, createDirector(d))
		default:
			configlogger.Error("Errow hile building hange spec: Unknown action type: %v", d.Action)
		}
	}
	return
}

func createService(service validator.Service) ConfigFunc {
	return func(h *Honeytrap) error {
		return h.CreateService(service.Name, service.Type, service.Director, service.Primitive)
	}
}
func removeService(service validator.Service) ConfigFunc {
	return func(h *Honeytrap) error {
		return fmt.Errorf("removeService not implemented")
	}
}
func serviceActions(specs []validator.Service) (add, remove []ConfigFunc) {
	for _, service := range specs {
		switch service.Action {
		case validator.IGNORE, validator.KEEP:
			// do nothing
		case validator.DISCARD:
			remove = append(remove, removeService(service))
		case validator.CREATE:
			add = append(add, createService(service))
		default:
			configlogger.Error("Error while building hange spec: Unknown action type: %v", service.Action)
		}
	}
	return
}

func createPort(p validator.Port) ConfigFunc {
	return func(h *Honeytrap) error {
		return h.CreatePort(p.Ports, p.Services)
	}
}
func removePort(p validator.Port) ConfigFunc {
	return func(h *Honeytrap) error {
		return fmt.Errorf("removePort not implemented")
	}
}
func portActions(specs []validator.Port) (add, remove []ConfigFunc) {
	for _, p := range specs {
		switch p.Action {
		case validator.IGNORE, validator.KEEP:
			// do nothing
		case validator.DISCARD:
			remove = append(remove, removePort(p))
		case validator.CREATE:
			add = append(add, createPort(p))
		default:
			configlogger.Error("Error while building hange spec: Unknown action type: %v", p.Action)
		}
	}
	return
}

func (c *ConfigManager) createActions(s validator.ConfigSpec) []ConfigFunc {
	removals := []ConfigFunc{}
	additions := []ConfigFunc{}

	a, b := channelActions(s.Channels)

	additions = append(additions, a...)
	removals = append(removals, b...)

	a, b = filterActions(s.Filters)

	additions = append(additions, a...)
	removals = append(removals, b...)

	a, b = directorActions(s.Directors)

	additions = append(additions, a...)
	removals = append(removals, b...)

	a, b = serviceActions(s.Services)

	additions = append(additions, a...)
	removals = append(removals, b...)

	a, b = portActions(s.Ports)

	additions = append(additions, a...)
	removals = append(removals, b...)

	return append(removals, additions...)
}

func (c *ConfigManager) Reconfigure(validata *validator.Validata) {

	//TODO: implement enhanced behaviour based on the aformentioned todo
	// generate implementation functions
	spec := validata.ConfigSpec()
	actions := c.createActions(spec)

	if len(actions) == 0 {
		c.Logger.Info("No configuration changes found.")
		return
	}

	c.Logger.Info("Passivating server")

	// When config is valid, tell system to passivate
	passivate := make(chan chan struct{}, 2)
	//fmt.Println("created channel")
	c.start <- passivate
	//fmt.Println("sent passivation thingy")
	ready := <-passivate
	//fmt.Println("received all clear")

	// Reconfigure Honeytrap
	c.Logger.Info("(Re)Configuring HoneyTrap...")

	for _, action := range actions {
		if err := action(c.Honeytrap); err != nil {
			c.Logger.Error("Error while applying new config: %s", err.Error())
			//TODO implement rollback. NOTE to self: that's though
		}
	}

	c.Honeytrap.config = spec.Config

	if c.Honeytrap.ui != nil {
		c.Honeytrap.PopulateServicesNode()
	}

	c.Logger.Info("Finished configuration changes")

	c.Validata = validata

	// Resume HoneyTrap when done
	ready <- struct{}{}
}

func (c *ConfigManager) Send(e event.Event) {
	if !(e.Get("category") == "configuration") {
		//fmt.Println(e.Get("category"), e.Get("sensor"), e.Get("sequence"))
		return // ignore non-config events
	}

	if e.Get("type") == "HONEYTRAP:UPDATE" {
		c.Logger.Info("Validating Config")

		if c.Validata == nil {
			c.Logger.Error("Could not perform config update. Initial Config hasn't been supplied.")
			return
		}

		file := e.Get("file")

		if file == "" {
			c.Logger.Error("Cannot read config file location")
			return
		}

		cfg := getConfig(file)

		v := validator.Validator{
			Replace:        false,
			RemoveExisting: false,
		}
		validata, err := v.Validate(c.Validata, cfg)

		if err != nil {
			log.Errorf("Error while reconfiguring: %s", err.Error())
			return
		}

		c.Reconfigure(validata)
		return
	}

	if e.Get("type") == "HONEYTRAP:OVERWRITE" {
		c.Logger.Info("Validating Config")

		if c.Validata == nil {
			c.Logger.Error("Could not perform config update. Initial Config hasn't been supplied.")
			return
		}

		file := e.Get("file")

		if file == "" {
			c.Logger.Error("Cannot read config file location")
			return
		}

		cfg := getConfig(file)

		v := validator.Validator{
			Replace:        false,
			RemoveExisting: true,
		}

		validata, err := v.Validate(c.Validata, cfg)

		if err != nil {
			log.Errorf("Error while reconfiguring: %s", err.Error())
			return
		}

		c.Reconfigure(validata)
		return
	}

	if e.Get("type") == "HONEYTRAP:INIT" {
		// TODO: Should change this to reading an input file
		c.Logger.Info("Validating Config")

		v := validator.Validator{
			Replace:        false,
			RemoveExisting: false,
		}

		validata, err := v.Validate(nil, c.Honeytrap.config)

		if err != nil {
			log.Errorf("Eror while reconfiguring: %s", err.Error())
			return
		}

		c.Reconfigure(validata)
	}
}

func (c *ConfigManager) Fake() {
	// fake
}

func (c *ConfigManager) PauseChan() chan chan chan struct{} {
	return c.start
}

type State int

const (
	QUIET State = 1 + iota
	PASSIVE
	ACTIVE
)

//NOTE remove this after presentation
func getConfig(path string) *config.Config {
	u, e := url.Parse(path)
	if e != nil {
		log.Error(e.Error())
		return nil
	}

	var data []byte

	if u.Scheme == "http" || u.Scheme == "https" {
		resp, err := http.Get(u.Path)
		if err != nil {
			log.Error(err.Error())
			return nil
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Error(err.Error())
			return nil
		}
		data = body
	} else {
		contents, err := ioutil.ReadFile(u.Path)
		if err != nil {
			log.Error(err.Error())
			return nil
		}
		data = contents
	}

	conf := config.Default
	conf.Load(bytes.NewBuffer(data))

	return &conf
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

	manager := NewConfigManager(hc)
	hc.bus.Subscribe(manager)

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

	if err := l.Start(ctx); err != nil {
		fmt.Println(color.RedString("Error starting listener: %s", err.Error()))
		return
	}

	hc.listnr = l

	// config of mini diplay
	if len(hc.config.MiniDisplay) == 0 {
		log.Info("Starting without MiniDisplay")
	} else {
		log.Info("Starting with Minidisplay")
		hc.CreateMiniDisplay()
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

	go func() {
		pause := manager.PauseChan()
		for {
			paused := <-pause
			//log.Info("Passivating")
			hc.State = PASSIVE
			wait := make(chan struct{}, 1)
			paused <- wait
			//log.Info("Ready to reconfigure")
			<-wait

			if hc.ui != nil {
				hc.ui.Refresh()
			}
			hc.State = ACTIVE
			//log.Info("Reconfigured, Resuming business")

		}
	}()

	go func() {
		time.Sleep(time.Second * 1)
		log.Info("Sending config event")
		hc.bus.Send(event.New(
			event.Sensor("honeytrap"),
			event.Category("configuration"),
			event.Type("HONEYTRAP:INIT"),
		))
		time.Sleep(time.Second * 2)
		log.Info("Sending config event")
		hc.bus.Send(event.New(
			event.Sensor("honeytrap"),
			event.Category("configuration"),
			event.Type("HONEYTRAP:UPDATE"),
			event.Custom("file", "./config-profile-3.toml"),
		))
		/*
			time.Sleep(time.Second * 3)
			log.Info("Sending config event")
			hc.bus.Send(event.New(
				event.Sensor("honeytrap"),
				event.Category("configuration"),
				event.Type("HONEYTRAP:OVERWRITE"),
				event.Custom("file", "./config-profile-1.toml"),
			))
		*/
	}()

	buffer := []net.Conn{}
	for {
		select {
		case <-ctx.Done():
			return
		case conn := <-incoming:
			if hc.State != ACTIVE {
				buffer = append(buffer, conn)
				continue
			}
			go hc.handle(conn)
		default:
			//NOTE is this safe?
			if hc.State == ACTIVE && len(buffer) > 0 {
				go hc.handle(buffer[0])
				buffer = buffer[1:]
			}
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
