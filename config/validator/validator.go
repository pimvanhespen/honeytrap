package validator

import (
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/honeytrap/honeytrap/config"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("honeytrap/config/validator")

type DecodeFunc func(toml.Primitive, interface{}) error

func parseMetaData(source toml.Primitive, target interface{}, decode DecodeFunc, kind string) bool {
	success := true
	if err := decode(source, target); err != nil {
		log.Error("Error parsing configuration of %s: %s", kind, err.Error())
		success = false
	}
	return success
}

type validata struct {
	*config.Config
	Channels  []*Channel
	Filters   []*Filter
	Directors []*Director
	Services  []*Service
	Ports     []*Port
}

func NewValidata(cfg *config.Config) *validata {
	return &validata{
		Config:    cfg,
		Channels:  []*Channel{},
		Filters:   []*Filter{},
		Directors: []*Director{},
		Services:  []*Service{},
		Ports:     []*Port{},
	}
}

/**
This function can decode channels, services etc.. and store relevant data in a metadata obejcts.
It is, indeed, not very pretty.. it'l remains so until golang has generics.
*/
func (v *validata) Prepare() {
	fn := v.Config.PrimitiveDecode

	logErr := func(typ string, err error) {
		log.Error("Error parsing configuration of %s: %s", typ, err.Error())
	}

	for key, primitive := range v.Config.Channels {
		tmp := ChannelMeta{}
		if err := fn(primitive, &tmp); err != nil {
			logErr("channel", err)
			continue
		}
		v.Channels = append(v.Channels, &Channel{
			Primitive: primitive,
			Meta:      &tmp,
			Name:      key,
		})
	}

	for _, primitive := range v.Config.Filters {
		tmp := FilterMeta{}
		if err := fn(primitive, &tmp); err != nil {
			logErr("filter", err)
			continue
		}
		for _, channel := range tmp.Channels {
			v.Filters = append(v.Filters, &Filter{
				Primitive: primitive,
				Target:    channel,
				Meta:      &tmp,
			})
		}
	}

	for _, primitive := range v.Config.Directors {
		tmp := DirectorMeta{}
		if err := fn(primitive, &tmp); err != nil {
			logErr("director", err)
			continue
		}
	}

	for key, primitive := range v.Config.Services {
		tmp := ServiceMeta{}
		if err := fn(primitive, &tmp); err != nil {
			logErr("service", err)
			continue
		}
		v.Services = append(v.Services, &Service{
			Meta:      &tmp,
			Name:      key,
			Primitive: primitive,
		})
	}

	for _, primitive := range v.Config.Ports {
		tmp := PortMeta{}
		if err := fn(primitive, &tmp); err != nil {
			logErr("port", err)
			continue
		}
		v.Ports = append(v.Ports, &Port{
			Primitive: primitive,
			Meta:      &tmp,
		})
	}
}

type ChannelMeta struct {
	Type string `toml:"type"`
}
type Channel struct {
	toml.Primitive
	Excluded bool
	Name     string
	Meta     *ChannelMeta
	Filters  []*Filter
}

func (c *Channel) Validate() {
	//TODO check if type is correct
}

type FilterMeta struct {
	Channels   []string `toml:"channel"`
	Services   []string `toml:"services"`
	Categories []string `toml:"categories"`
}
type Filter struct {
	toml.Primitive
	Excluded bool
	Target   string
	Meta     *FilterMeta
	*Channel            //link
	Services []*Service //link
}

func (f *Filter) Validate() {
	if len(f.Meta.Services) == 0 {
		log.Error("No services configured for filter. %s", f.Dump())
		f.Excluded = true
		return // no need for further checking?
	}
}

func (f *Filter) Dump() string {
	return fmt.Sprintf("target channel: '%s'; config from file: Channels:%v, Services:%v, Categories: %v", f.Target, f.Meta.Channels, f.Meta.Services, f.Meta.Categories)
}

type DirectorMeta struct {
	Type string `toml:"type"`
}
type Director struct {
	toml.Primitive
	Excluded bool
	Meta     *DirectorMeta
	Services []*Service //link
}

func (d *Director) Validate() {
	if "" == d.Meta.Type {
		log.Error("Type not set for director")
		d.Excluded = true
		return // no need for further checking?
	}
	//TODO check if type exists
}

type ServiceMeta struct {
	Type     string `toml:"type"`
	Director string `toml:"director"`
	Port     string `toml:"port"`
}
type Service struct {
	toml.Primitive
	Excluded bool
	Meta     *ServiceMeta
	Name     string
	*Director
	Ports   []*Port //link
	Filters []*Filter
}

func (s *Service) Validate() {
	if "" == s.Meta.Type {
		log.Error("Service type not set for service '%s'", s.Name)
		s.Excluded = true
		return // no need for further checking...
	}

	if "" != s.Meta.Port {
		log.Warning("Configuring ports for services is deprecated. define services for ports instead")
	}
}

type PortMeta struct {
	Port     string   `toml:"port"`
	Ports    []string `toml:"ports"`
	Services []string `toml:"services"`
}
type Port struct {
	toml.Primitive
	Excluded bool
	Meta     *PortMeta
	Services []*Service //link
}

func (p *Port) Validate() {
	var ports []string
	if p.Meta.Ports != nil {
		ports = p.Meta.Ports
	}
	if p.Meta.Port != "" {
		ports = append(ports, p.Meta.Port)
	}
	if p.Meta.Port != "" && p.Meta.Ports != nil {
		log.Warning("Both \"port\" and \"ports\" were defined, this can be confusing")
	} else if p.Meta.Port == "" && p.Meta.Ports == nil {
		log.Error("Neither \"port\" nor \"ports\" were defined")
		p.Excluded = true
		return
	}
}

func (p *Port) Dump() string {
	return fmt.Sprintf("Port: %v, Ports: %v, services: %v", p.Meta.Port, p.Meta.Ports, p.Meta.Services)
}

func (v *validata) GetChannel(wanted string) *Channel {
	for _, channel := range v.Channels {
		if !channel.Excluded && channel.Name == wanted {
			return channel
		}
	}
	return nil
}
func (v *validata) GetService(wanted string) *Service {
	for _, service := range v.Services {
		if !service.Excluded && service.Name == wanted {
			return service
		}
	}
	return nil
}
func (v *validata) GetDirector(wanted string) *Director {
	for _, director := range v.Directors {
		if !director.Excluded && director.Meta.Type == wanted {
			return director
		}
	}
	return nil
}

// No need for generics... Right? >.<
func (v *validata) GetChannels() (result []*Channel) {
	for _, channel := range v.Channels {
		if !channel.Excluded {
			result = append(result, channel)
		}
	}
	return
}
func (v *validata) GetFilters() (result []*Filter) {
	for _, item := range v.Filters {
		if !item.Excluded {
			result = append(result, item)
		}
	}
	return
}
func (v *validata) GetDirectors() (result []*Director) {
	for _, item := range v.Directors {
		if !item.Excluded {
			result = append(result, item)
		}
	}
	return
}
func (v *validata) GetServices() (result []*Service) {
	for _, item := range v.Services {
		if !item.Excluded {
			result = append(result, item)
		}
	}
	return
}
func (v *validata) GetPorts() (result []*Port) {
	for _, item := range v.Ports {
		if !item.Excluded {
			result = append(result, item)
		}
	}
	return
}

func strListMatches(a, b []string) (c []string) {
	for _, aa := range a {
		for _, bb := range b {
			if aa == bb {
				c = append(c, aa)
			}
		}
	}
	return
}

// Validate validates a single config file. do not use this for comparisons...
func Validate(cfg *config.Config) bool {
	log.Info("Validating configuration.... ")
	log.Info("Validation available for channels, filters, directors, services and ports")
	v := NewValidata(cfg)

	// load data into a validation object.
	v.Prepare()

	// TODO: Self-validate
	// Does service type exist? are ports correctly configured?, etc
	// for _,service := range v.Service {
	//     service.Validate() // set Excluded to true if service is useless.
	// }

	for _, item := range v.Channels {
		item.Validate()
	}
	for _, item := range v.Filters {
		item.Validate()
	}
	for _, item := range v.Directors {
		item.Validate()
	}
	for _, item := range v.Services {
		item.Validate()
	}
	for _, item := range v.Ports {
		item.Validate()
	}

	// Duplicates?
	// dont check for duplicatres here... This is for a single file

	// LINK: Filter --> channel
	for _, filter := range v.Filters {
		channel := v.GetChannel(filter.Target)
		if channel == nil {
			// ignore this filter, it won't write to anything. It's useless.
			log.Error("Could not find channel '%s' for filter", filter.Target)
			filter.Excluded = true
			continue
		}
		// LINK!
		channel.Filters = append(channel.Filters, filter)
		filter.Channel = channel
	}

	//TODO: check for channels with no filter
	for _, channel := range v.Channels {
		if 0 == len(channel.Filters) {
			log.Error("No filters configured for channel '%s', type: '%s'", channel.Name, channel.Meta.Type)
			channel.Excluded = true
		}
	}

	// LINK: Service --> director
	// If a service cannot be linked to any director, it should not be used
	for _, service := range v.Services {
		directorName := service.Meta.Director
		if "" == directorName {
			continue // no director set, do not check if director exists
		}

		director := v.GetDirector(directorName)
		if nil == director {
			log.Error("No director of type '%s' found for service '%s'", directorName, service.Name)
			service.Excluded = true
			continue //ignore this service...
		}
		// LINK!
		service.Director = director
		director.Services = append(director.Services, service)
	}

	// TODO: check for directors with no service

	// LINK: Filter --> Services
	// check if services exist (non-blockingfatal for a channel... )
	// filters with no services are excluded
	for _, filter := range v.Filters {

		// is this filter filtering services?
		if len(filter.Meta.Services) == 0 {
			//no service filtering
			continue
		}

		for _, name := range filter.Meta.Services {
			service := v.GetService(name)
			if service == nil {
				log.Warning("Unrecognized service '%s' for filter", name)
				continue
			}

			// LINK!
			service.Filters = append(service.Filters, filter)
			filter.Services = append(filter.Services, service)
		}
		if 0 == len(filter.Services) {
			log.Error("No services found for filter with config: %s", filter.Dump())
			filter.Excluded = true
		}
	}

	// LINK: Port --> Service
	// matches services to port IF the services have not been excluded for config errors
	for _, port := range v.Ports {
		services := port.Meta.Services
		log.Infof("Checking port %s", port.Dump())
		if 0 == len(services) {
			log.Error("No services configured for port with config: %s", port.Dump())
			port.Excluded = true
			continue
		}

		for _, serviceName := range services {
			service := v.GetService(serviceName)
			if nil == service {
				log.Warning("Service '%s' not found for port", serviceName)
				continue
			}

			// LINK!
			port.Services = append(port.Services, service)
			service.Ports = append(service.Ports, port)
		}
		// check if there are any services connected to the port
		if 0 == len(port.Services) {
			// no services connected
			log.Error("No usable services found for port. wanted: %v. Did a service fail to configure?", services)
			port.Excluded = true
		}
	}

	// Check if all services are connected to ports
	for _, service := range v.Services {
		if 0 == len(service.Ports) {
			log.Error("No ports configured for service '%s'", service.Name)
			service.Excluded = true
		}
	}

	for _, item := range v.GetChannels() {
		fmt.Println(item)
	}
	for _, item := range v.GetFilters() {
		fmt.Println(item)
	}
	for _, item := range v.GetDirectors() {
		fmt.Println(item)
	}
	for _, item := range v.GetServices() {
		fmt.Println(item)
	}
	for _, item := range v.GetPorts() {
		fmt.Println(item)
	}

	//NOTE: for compare: Check for outside links -- NOT HERE

	// create stuff (final check)
	// channels
	// filters
	// directors
	// services
	// ports

	// all fine? return compiled config (or new config?)
	return false
}
