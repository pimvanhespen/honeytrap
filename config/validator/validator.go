package validator

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/honeytrap/honeytrap/config"
	logging "github.com/op/go-logging"

	"github.com/honeytrap/honeytrap/director"
	"github.com/honeytrap/honeytrap/pushers"
	"github.com/honeytrap/honeytrap/services"
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

type channelMeta struct {
	Type string `toml:"type"`
}
type channelData struct {
	toml.Primitive
	Excluded bool
	Name     string
	Meta     *channelMeta
	Filters  []*filterData
}

func (c *channelData) Validate() {
	_, ok := pushers.Get(c.Meta.Type)
	if !ok {
		log.Error("Channel %s not supported on platform (%s)", c.Meta.Type, c.Name)
		c.Excluded = true
		return
	}
}
func (c *channelData) String() string {
	return fmt.Sprintf("Channel[ name: %s, type: %s]", c.Name, c.Meta.Type)
}

type filterMeta struct {
	Channels   []string `toml:"channel"`
	Services   []string `toml:"services"`
	Categories []string `toml:"categories"`
}
type filterData struct {
	toml.Primitive
	Excluded     bool
	Target       string
	Meta         *filterMeta
	*channelData                //link
	Services     []*serviceData //link
}

func (f *filterData) String() string {
	svs := []string{}
	for _, x := range f.Services {
		svs = append(svs, x.Name)
	}
	return fmt.Sprintf("Filter[ type: %s, services:%v, cats: %v]", f.Target, svs, f.Meta.Categories)
}
func (f *filterData) Validate() {
	// no validation needed here...
	// A filter only links, doensn't have any private config
}
func (f *filterData) Dump() string {
	return fmt.Sprintf("target channel: '%s'; config from file: Channels:%v, Services:%v, Categories: %v", f.Target, f.Meta.Channels, f.Meta.Services, f.Meta.Categories)
}

type directorMeta struct {
	Type string `toml:"type"`
}
type directorData struct {
	toml.Primitive
	Excluded bool
	Name     string
	Meta     *directorMeta
	Services []*serviceData //link
}

func (d *directorData) String() string {
	return fmt.Sprintf("Director[ type: %s]", d.Meta.Type)
}
func (d *directorData) Validate() {
	if "" == d.Meta.Type {
		log.Error("Type not set for director")
		d.Excluded = true
		return // no need for further checking?
	}
	_, ok := director.Get(d.Meta.Type)
	if !ok {
		log.Error("Director %s not supported on platform", d.Meta.Type)
		d.Excluded = true
		return
	}
	//TODO check if type exists
}

type serviceMeta struct {
	Type     string `toml:"type"`
	Director string `toml:"director"`
	Port     string `toml:"port"`
}
type serviceData struct {
	toml.Primitive
	Excluded bool
	Meta     *serviceMeta
	Name     string
	*directorData
	Ports   []*portData //link
	Filters []*filterData
}

func (s *serviceData) String() string {
	return fmt.Sprintf("Service[ name: %s, type: %s, director: %v]", s.Name, s.Meta.Type, s.Meta.Director)
}
func (s *serviceData) Validate() {
	if "" == s.Meta.Type {
		log.Error("Service type not set for service '%s'", s.Name)
		s.Excluded = true
		return // no need for further checking...
	}

	_, ok := services.Get(s.Meta.Type)
	if !ok {
		log.Error("Service '%s' not supported on platform (%s)", s.Meta.Type, s.Name)
		s.Excluded = true
		return
	}

	if "" != s.Meta.Port {
		log.Warning("Configuring ports for services is deprecated. define services for ports instead")
	}
}

type portMeta struct {
	Port     string   `toml:"port"`
	Ports    []string `toml:"ports"`
	Services []string `toml:"services"`
}
type portData struct {
	toml.Primitive
	Excluded bool
	Meta     *portMeta
	Services []*serviceData //link
}

func (p *portData) String() string {
	svs := []string{}
	for _, x := range p.Services {
		svs = append(svs, x.Name)
	}
	return fmt.Sprintf("Port[ port: %s, ports: %v, services: %v]", p.Meta.Port, p.Meta.Ports, p.Meta.Services)
}
func (p *portData) Validate() {
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
func (p *portData) Dump() string {
	return fmt.Sprintf("Port: %v, Ports: %v, services: %v", p.Meta.Port, p.Meta.Ports, p.Meta.Services)
}

type validata struct {
	*config.Config
	Channels  []*channelData
	Filters   []*filterData
	Directors []*directorData
	Services  []*serviceData
	Ports     []*portData
}

func newValidata(cfg *config.Config) *validata {
	return &validata{
		Config:    cfg,
		Channels:  []*channelData{},
		Filters:   []*filterData{},
		Directors: []*directorData{},
		Services:  []*serviceData{},
		Ports:     []*portData{},
	}
}

//Prepare This function can decode channels, services etc.. and store relevant data in a metadata obejcts.
//It is, indeed, not very pretty.. it'l remains so until golang has generics.
func (v *validata) Prepare() {
	fn := v.Config.PrimitiveDecode

	logErr := func(typ string, err error) {
		log.Error("Error parsing configuration of %s: %s", typ, err.Error())
	}

	for key, primitive := range v.Config.Channels {
		tmp := channelMeta{}
		if err := fn(primitive, &tmp); err != nil {
			logErr("channel", err)
			continue
		}
		v.Channels = append(v.Channels, &channelData{
			Primitive: primitive,
			Meta:      &tmp,
			Name:      key,
		})
	}

	for _, primitive := range v.Config.Filters {
		tmp := filterMeta{}
		if err := fn(primitive, &tmp); err != nil {
			logErr("filter", err)
			continue
		}
		for _, channel := range tmp.Channels {
			// COPY meta data
			meta := tmp
			// replace channels for the single channel to use
			meta.Channels = []string{channel}

			// Create new primitive, for this filter only...
			var buffer bytes.Buffer

			e := toml.NewEncoder(&buffer)
			if err := e.Encode(meta); err != nil {
				log.Error(err.Error())
				continue
			}

			//New Primtive, containing data for a filter for one channel
			var newPrimitive toml.Primitive

			if _, err := toml.DecodeReader(strings.NewReader(buffer.String()), &newPrimitive); err != nil {
				log.Error(err.Error())
				continue
			}

			filter := &filterData{
				Primitive: newPrimitive,
				Target:    channel,
				Meta:      &meta,
			}
			v.Filters = append(v.Filters, filter)
		}
	}

	for key, primitive := range v.Config.Directors {
		tmp := directorMeta{}
		if err := fn(primitive, &tmp); err != nil {
			logErr("director", err)
			continue
		}
		v.Directors = append(v.Directors, &directorData{
			Primitive: primitive,
			Meta:      &tmp,
			Name:      key,
		})
	}

	for key, primitive := range v.Config.Services {
		tmp := serviceMeta{}
		if err := fn(primitive, &tmp); err != nil {
			logErr("service", err)
			continue
		}
		v.Services = append(v.Services, &serviceData{
			Meta:      &tmp,
			Name:      key,
			Primitive: primitive,
		})
	}

	for _, primitive := range v.Config.Ports {
		tmp := portMeta{}
		if err := fn(primitive, &tmp); err != nil {
			logErr("port", err)
			continue
		}
		v.Ports = append(v.Ports, &portData{
			Primitive: primitive,
			Meta:      &tmp,
		})
	}

}

// dumps unsued keys in config to log
func (v *validata) UnusedConfig() {
	if len(v.Config.Undecoded()) > 0 {
		log.Warningf("Unrecognized keys in configuration: %v", v.Config.Undecoded())
	}

}

// GetChannel returns the requested Channel object, if the object isn't marked as excluded
func (v *validata) GetChannel(wanted string) *channelData {
	for _, channel := range v.Channels {
		if !channel.Excluded && channel.Name == wanted {
			return channel
		}
	}
	return nil
}

// GetService returns the requested Service object, if the object isn't marked as excluded
func (v *validata) GetService(wanted string) *serviceData {
	for _, service := range v.Services {
		if !service.Excluded && service.Name == wanted {
			return service
		}
	}
	return nil
}

// GetDirector returns the requested object, if the object isnt marked as excluded
func (v *validata) GetDirector(wanted string) *directorData {
	for _, director := range v.Directors {
		if !director.Excluded && director.Meta.Type == wanted {
			return director
		}
	}
	return nil
}

// GetChannels returns all channels that aren't marked as excluded
func (v *validata) GetChannels() (result []*channelData) {
	for _, channel := range v.Channels {
		if !channel.Excluded {
			result = append(result, channel)
		}
	}
	return
}

// GetFilters returns all filterss that aren't marked as excluded
func (v *validata) GetFilters() (result []*filterData) {
	for _, item := range v.Filters {
		if !item.Excluded {
			result = append(result, item)
		}
	}
	return
}

// GetDirectors returns all directors that aren't marked as excluded
func (v *validata) GetDirectors() (result []*directorData) {
	for _, item := range v.Directors {
		if !item.Excluded {
			result = append(result, item)
		}
	}
	return
}

// GetServices returns all services that aren't marked as excluded
func (v *validata) GetServices() (result []*serviceData) {
	for _, item := range v.Services {
		if !item.Excluded {
			result = append(result, item)
		}
	}
	return
}

// GetPorts returns all ports that aren't marked as excluded
func (v *validata) GetPorts() (result []*portData) {
	for _, item := range v.Ports {
		if !item.Excluded {
			result = append(result, item)
		}
	}
	return
}

// SelfValidate this method call the 'Validate()' method on all of its objects (Services filters, etc.)
//Excludes all objects that find themselves invalid. DOES NOT CHECK LINKS BETWEEN OBJECTS!
func (v *validata) SelfValidate() {
	for _, item := range v.GetChannels() {
		item.Validate()
	}
	for _, item := range v.GetFilters() {
		item.Validate()
	}
	for _, item := range v.GetDirectors() {
		item.Validate()
	}
	for _, item := range v.GetServices() {
		item.Validate()
	}
	for _, item := range v.GetPorts() {
		item.Validate()
	}
}

// Copy Returnsa copy of the original 'validata'-object conting only the valid data
//object marked as excluded will be excluded accordingly
func (v *validata) Copy(excluded bool) *validata {
	if excluded {
		return nil // not supported yet
	}
	return &validata{
		Channels:  v.GetChannels(),
		Filters:   v.GetFilters(),
		Directors: v.GetDirectors(),
		Services:  v.GetServices(),
		Ports:     v.GetPorts(),
	}
}

//String returns a string representations of the object
func (v *validata) String() string {
	result := "Validata[\n"
	for _, x := range v.GetChannels() {
		result += "\t" + x.String() + "\n"
	}
	for _, x := range v.GetFilters() {
		result += "\t" + x.String() + "\n"
	}
	for _, x := range v.GetDirectors() {
		result += "\t" + x.String() + "\n"
	}
	for _, x := range v.GetServices() {
		result += "\t" + x.String() + "\n"
	}
	for _, x := range v.GetPorts() {
		result += "\t" + x.String() + "\n"
	}
	result += "]\n"
	return result
}

func (v *validata) ToConfig() *config.Config {
	// Copy default settings (there's no implementation for changes to these settings yet) #TODO
	result := config.Default
	result.Listener = v.Config.Listener
	result.Web = v.Config.Web
	result.Logging = v.Config.Logging
	result.MiniDisplay = v.Config.MiniDisplay

	// Copy not excluded channels
	for _, channel := range v.GetChannels() {
		result.Channels[channel.Name] = channel.Primitive
	}
	// and filters
	for _, filter := range v.GetFilters() {
		result.Filters = append(result.Filters, filter.Primitive)
	}
	// and ports
	for _, port := range v.GetPorts() {
		result.Ports = append(result.Ports, port.Primitive)
	}
	// and directors
	for _, dir := range v.GetDirectors() {
		result.Directors[dir.Name] = dir.Primitive
	}
	// and finally, services
	for _, serv := range v.GetServices() {
		result.Services[serv.Name] = serv.Primitive
	}

	// return the new config object
	return &result
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

func strInList(str string, list []string) bool {
	for _, item := range list {
		if str == item {
			return true
		}
	}
	return false
}

// Validate validates a single config file. do not use this for comparisons...
func Validate(conf *config.Config) *config.Config {
	log.Info("Validating configuration... Validating Channels, Filters, Directors, Services and Ports.")

	v := newValidata(conf)

	// load data into a validation object.
	v.Prepare()
	// all items should self validate (e.g. is their private config o.k.)
	// this check ignores links to other objects
	v.SelfValidate()

	// Duplicates?
	// dont check for duplicatres here... This is for a single file

	// LINK: Filter --> channel
	for _, filter := range v.GetFilters() {
		channel := v.GetChannel(filter.Target)
		if channel == nil {
			// ignore this filter, it won't write to anything. It's useless.
			log.Error("Could not find channel '%s' for filter", filter.Target)
			filter.Excluded = true
			continue
		}
		// LINK!
		channel.Filters = append(channel.Filters, filter)
		filter.channelData = channel
	}

	// check for channels with no filter (unused channels)
	for _, channel := range v.GetChannels() {
		if 0 == len(channel.Filters) {
			log.Error("No filters configured for channel '%s', type: '%s'", channel.Name, channel.Meta.Type)
			channel.Excluded = true
			continue
		}
	}

	// LINK: Service --> director
	// If a service cannot be linked to any director, it should not be used
	// if a service has a direc specified, but cannot be linked to it, ignore the service definition
	for _, service := range v.GetServices() {
		directorName := service.Meta.Director
		if "" == directorName {
			continue // no director set, do not check if director exists
		}

		d := v.GetDirector(directorName)
		if nil == d {
			log.Error("No director of type '%s' found for service '%s'", directorName, service.Name)
			service.Excluded = true
			continue //ignore this service...
		}
		// LINK!
		service.directorData = d
		d.Services = append(d.Services, service)
	}

	// check for unused directors
	for _, d := range v.GetDirectors() {
		if 0 == len(d.Services) {
			log.Error("Director '%s' unused, excluding it from config", d.Meta.Type)
			d.Excluded = true
			continue
		}
	}

	// LINK: Filter --> Services
	// check if services exist (non-blockingfatal for a channel... )
	// filters with no services are excluded
	for _, filter := range v.GetFilters() {

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
	for _, port := range v.GetPorts() {
		s := port.Meta.Services
		//log.Infof("Checking port %s", port.Dump())
		if 0 == len(s) {
			log.Error("No services configured for port with config: %s", port.Dump())
			port.Excluded = true
			continue
		}

		for _, serviceName := range s {
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
			log.Error("No usable services found for port. wanted: %v. Did a service fail to configure?", port.Meta.Services)
			port.Excluded = true
			continue
		}
	}

	// Check if all services are assinged to ports
	for _, service := range v.GetServices() {
		if 0 == len(service.Ports) {
			log.Error("No ports configured for service '%s'", service.Name)
			service.Excluded = true
		}
	}

	//NOTE: for compare: Check for outside links -- NOT HERE
	v.UnusedConfig()
	return v.ToConfig()
}
