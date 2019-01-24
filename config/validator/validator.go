package validator

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/honeytrap/honeytrap/config"
	logging "github.com/op/go-logging"

	"github.com/honeytrap/honeytrap/director"
	"github.com/honeytrap/honeytrap/pushers"
	"github.com/honeytrap/honeytrap/services"
)

type Action int

const (
	KEEP = iota
	DISCARD
	CREATE
	IGNORE // in case of bad config or ignored newer definition
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

// PRIVATE structs & methods
// used for decoding purposes only (just about everything)
type channelMeta struct {
	Type string `toml:"type"`
}
type channelData struct {
	toml.Primitive
	Action
	Name    string
	Meta    *channelMeta
	Filters []*filterData
}
type Channel struct {
	Action
	toml.Primitive
	Type string
	Name string
}

func (c *channelData) Validate() {
	_, ok := pushers.Get(c.Meta.Type)
	if !ok {
		log.Error("Channel %s not supported on platform (%s)", c.Meta.Type, c.Name)
		c.Action = IGNORE
		return
	}
}
func (c *channelData) String() string {
	return fmt.Sprintf("Channel[ name: %s, type: %s]", c.Name, c.Meta.Type)
}
func (c *channelData) Equals(other *channelData) bool {
	return c.Name == other.Name
}
func (c *channelData) Exclude() {
	c.Action = IGNORE
}
func (c *channelData) Export() Channel {
	return Channel{
		Action:    c.Action,
		Primitive: c.Primitive,
		Type:      c.Meta.Type,
		Name:      c.Name,
	}
}

type filterMeta struct {
	Channels   []string `toml:"channel"`
	Services   []string `toml:"services"`
	Categories []string `toml:"categories"`
}
type filterData struct {
	toml.Primitive
	Action
	Target       string
	Meta         *filterMeta
	*channelData                //link
	Services     []*serviceData //link
}
type Filter struct {
	Action
	toml.Primitive
	Target     string
	Services   []string
	Categories []string
}

func strListCmp(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sort.Strings(a)
	sort.Strings(b)

	for i, item := range a {
		if item != b[i] {
			return false
		}
	}
	return true
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
func (f *filterData) Equals(other *filterData) bool {
	if f.Target != other.Target {
		return false
	}
	if !strListCmp(f.Meta.Services, other.Meta.Services) {
		return false
	}

	return strListCmp(f.Meta.Categories, other.Meta.Categories)
}
func (f *filterData) Exclude() {
	f.Action = IGNORE
}
func (f *filterData) Export() Filter {
	return Filter{
		Action:     f.Action,
		Primitive:  f.Primitive,
		Target:     f.Target,
		Services:   f.Meta.Services,
		Categories: f.Meta.Categories,
	}
}

type directorMeta struct {
	Type string `toml:"type"`
}
type directorData struct {
	toml.Primitive
	Action
	Name     string
	Meta     *directorMeta
	Services []*serviceData //link
}
type Director struct {
	Action
	toml.Primitive
	Name string
	Type string
}

func (d *directorData) String() string {
	return fmt.Sprintf("Director[ type: %s]", d.Meta.Type)
}
func (d *directorData) Validate() {
	if "" == d.Meta.Type {
		log.Error("Type not set for director")
		d.Action = IGNORE
		return // no need for further checking?
	}
	_, ok := director.Get(d.Meta.Type)
	if !ok {
		log.Error("Director %s not supported on platform", d.Meta.Type)
		d.Action = IGNORE
		return
	}
	//TODO check if type exists
}
func (d *directorData) Equals(other *directorData) bool {
	return d.Name == other.Name
}
func (d *directorData) Exclude() {
	d.Action = IGNORE
}
func (d *directorData) Export() Director {
	return Director{
		Action:    d.Action,
		Primitive: d.Primitive,
		Name:      d.Name,
		Type:      d.Meta.Type,
	}
}

type serviceMeta struct {
	Type     string `toml:"type"`
	Director string `toml:"director"`
	Port     string `toml:"port"`
}
type serviceData struct {
	toml.Primitive
	Action
	Meta *serviceMeta
	Name string
	*directorData
	Ports   []*portData //link
	Filters []*filterData
}
type Service struct {
	Action
	toml.Primitive
	Type     string
	Name     string
	Director string
}

func (s *serviceData) String() string {
	return fmt.Sprintf("Service[ name: %s, type: %s, director: %v]", s.Name, s.Meta.Type, s.Meta.Director)
}
func (s *serviceData) Validate() {
	if "" == s.Meta.Type {
		log.Error("Service type not set for service '%s'", s.Name)
		s.Action = IGNORE
		return // no need for further checking...
	}

	_, ok := services.Get(s.Meta.Type)
	if !ok {
		log.Error("Service '%s' not supported on platform (%s)", s.Meta.Type, s.Name)
		s.Action = IGNORE
		return
	}

	if "" != s.Meta.Port {
		log.Warning("Configuring ports for services is deprecated. define services for ports instead")
	}
}
func (s *serviceData) Equals(other *serviceData) bool {
	return s.Name == other.Name
}
func (s *serviceData) Exclude() {
	s.Action = IGNORE
}
func (s *serviceData) Export() Service {
	return Service{
		Action:    s.Action,
		Primitive: s.Primitive,
		Type:      s.Meta.Type,
		Name:      s.Name,
		Director:  s.Meta.Director,
	}
}

type portMeta struct {
	Port     string   `toml:"port"`
	Ports    []string `toml:"ports"`
	Services []string `toml:"services"`
}
type portData struct {
	toml.Primitive
	Action
	Meta     *portMeta
	Services []*serviceData //link
	Ports    []net.Addr
}
type Port struct {
	Action
	toml.Primitive
	Services []string
	Ports    []net.Addr
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
		p.Action = IGNORE
		return
	}

	for _, portStr := range ports {
		addr, _, _, err := config.ToAddr(portStr)
		if err != nil {
			log.Error("Error parsing port string (%s): %s", portStr, err.Error())
			p.Action = IGNORE
			return
		}
		if addr == nil {
			log.Error("Failed to bind: addr is nil")
			p.Action = IGNORE
			return
		}
		p.Ports = append(p.Ports, addr)
	}
}
func (p *portData) Dump() string {
	return fmt.Sprintf("Port: %v, Ports: %v, services: %v", p.Meta.Port, p.Meta.Ports, p.Meta.Services)
}
func (p *portData) Name() string {
	var ports []string
	if len(p.Meta.Ports) > 0 {
		ports = p.Meta.Ports
	}
	if len(p.Meta.Port) > 0 {
		ports = append(ports, p.Meta.Port)
	}
	return strings.Join(ports, ",")
}
func (p *portData) Overlapping(other *portData) []net.Addr {
	result := []net.Addr{}
	for _, local := range p.Ports {
		for _, ext := range other.Ports {
			if config.CompareAddr(local, ext) {
				result = append(result, local)
			}
		}
	}
	return result
}
func (p *portData) Equals(other *portData) bool {
	return len(p.Overlapping(other)) > 0
}
func (p *portData) Exclude() {
	p.Action = IGNORE
}
func (p *portData) Export() Port {
	return Port{
		Action:    p.Action,
		Primitive: p.Primitive,
		Services:  p.Meta.Services,
		Ports:     p.Ports,
	}
}

// The master-strcut, this struct contains all data that's required to validate a <<SINGLE>> config file
type Validata struct {
	*config.Config
	Channels  []*channelData
	Filters   []*filterData
	Directors []*directorData
	Services  []*serviceData
	Ports     []*portData
	prepared  bool
}

func newValidata(cfg *config.Config) *Validata {
	data := &Validata{
		Config: cfg,
	}
	return data
}

func (v *Validata) Prepare(action Action) {
	if v.prepared {
		v.prepareOld(action)
	} else {
		v.prepareNew(action)
	}
}

func (v *Validata) prepareOld(action Action) {
	v.Channels = v.GetChannels()
	for _, x := range v.Channels {
		x.Action = action
	}

	v.Filters = v.GetFilters()
	for _, x := range v.Filters {
		x.Action = action
	}

	v.Directors = v.GetDirectors()
	for _, x := range v.Directors {
		x.Action = action
	}

	v.Services = v.GetServices()
	for _, x := range v.Services {
		x.Action = action
	}

	v.Ports = v.GetPorts()
	for _, x := range v.Ports {
		x.Action = action
	}
}

//Prepare This function can decode channels, services etc.. and store relevant data in a metadata obejcts.
//It is, indeed, not very pretty.. it'l remains so until golang has generics.
func (v *Validata) prepareNew(action Action) {
	// set prepared = true
	v.prepared = true

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
			Action:    action,
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
				Action:    action,
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
			Action:    action,
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
			Action:    action,
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
			Action:    action,
		})
	}

}

// dumps unsued keys in config to log
func (v *Validata) UnusedConfig() {
	if len(v.Config.Undecoded()) > 0 {
		log.Warningf("Unrecognized keys in configuration: %v", v.Config.Undecoded())
	}

}

// GetChannel returns the requested Channel object, if the object isn't marked as excluded
func (v *Validata) GetChannel(wanted string) *channelData {
	for _, channel := range v.Channels {
		if !inactiveState(channel.Action) && channel.Name == wanted {
			return channel
		}
	}
	return nil
}

// GetService returns the requested Service object, if the object isn't marked as excluded
func (v *Validata) GetService(wanted string) *serviceData {
	for _, service := range v.Services {
		if !inactiveState(service.Action) && service.Name == wanted {
			return service
		}
	}
	return nil
}

// GetDirector returns the requested object, if the object isnt marked as excluded
func (v *Validata) GetDirector(wanted string) *directorData {
	for _, director := range v.Directors {
		if !inactiveState(director.Action) && director.Meta.Type == wanted {
			return director
		}
	}
	return nil
}

// GetChannels returns all channels that aren't marked as excluded
func (v *Validata) GetChannels() (result []*channelData) {
	for _, channel := range v.Channels {
		if !inactiveState(channel.Action) {
			result = append(result, channel)
		}
	}
	return
}

// GetFilters returns all filterss that aren't marked as excluded
func (v *Validata) GetFilters() (result []*filterData) {
	for _, item := range v.Filters {
		if !inactiveState(item.Action) {
			result = append(result, item)
		}
	}
	return
}

// GetDirectors returns all directors that aren't marked as excluded
func (v *Validata) GetDirectors() (result []*directorData) {
	for _, item := range v.Directors {
		if !inactiveState(item.Action) {
			result = append(result, item)
		}
	}
	return
}

// GetServices returns all services that aren't marked as excluded
func (v *Validata) GetServices() (result []*serviceData) {
	for _, item := range v.Services {
		if !inactiveState(item.Action) {
			result = append(result, item)
		}
	}
	return
}

// GetPorts returns all ports that aren't marked as excluded
func (v *Validata) GetPorts() (result []*portData) {
	for _, item := range v.Ports {
		if !inactiveState(item.Action) {
			result = append(result, item)
		}
	}
	return
}

// SelfValidate this method call the 'Validate()' method on all of its objects (Services filters, etc.)
//Excludes all objects that find themselves invalid. DOES NOT CHECK LINKS BETWEEN OBJECTS!
func (v *Validata) SelfValidate() {
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
func (v *Validata) Copy(excluded bool) *Validata {
	if excluded {
		return nil // not supported yet
	}
	return &Validata{
		Channels:  v.GetChannels(),
		Filters:   v.GetFilters(),
		Directors: v.GetDirectors(),
		Services:  v.GetServices(),
		Ports:     v.GetPorts(),
	}
}

//String returns a string representations of the object
func (v *Validata) String() string {
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

//ToConfig builds a config.Config object from the valid config items
func (v *Validata) ToConfig() *config.Config {
	// Copy default settings (there's no implementation for changes to these settings yet) #TODO
	// copying config because half of the settings will stay the same, and it prevents the need init
	// toml.MetaData. A toml.MetaData struct cannot be create outside the package (it can, but usage
	// of underlying maps will retur an exception). Which kames it impossible
	// to correctly decode later servicespecific stuff on in the Honeytrap...
	result := v.Config
	result.Channels = map[string]toml.Primitive{}
	result.Filters = []toml.Primitive{}
	result.Ports = []toml.Primitive{}
	result.Directors = map[string]toml.Primitive{}
	result.Services = map[string]toml.Primitive{}

	// Copy not excluded channels
	for _, channel := range v.GetChannels() {
		result.Channels[channel.Name] = channel.Primitive
	}
	//fmt.Println(result.Channels)

	// and filters
	for _, filter := range v.GetFilters() {
		result.Filters = append(result.Filters, filter.Primitive)
	}
	//fmt.Println(result.Filters)

	// and ports
	for _, port := range v.GetPorts() {
		result.Ports = append(result.Ports, port.Primitive)
	}
	//fmt.Println(result.Ports)

	// and directors
	for _, dir := range v.GetDirectors() {
		result.Directors[dir.Name] = dir.Primitive
	}
	//fmt.Println(result.Directors)

	// and finally, services
	for _, serv := range v.GetServices() {
		result.Services[serv.Name] = serv.Primitive
	}

	return result
}

func (v *Validata) ConfigSpec() ConfigSpec {
	channels := make([]Channel, len(v.Channels))
	for i, x := range v.Channels {
		channels[i] = x.Export()
	}
	filters := make([]Filter, len(v.Filters))
	for i, x := range v.Filters {
		filters[i] = x.Export()
	}
	dirs := make([]Director, len(v.Directors))
	for i, x := range v.Directors {
		dirs[i] = x.Export()
	}
	services := make([]Service, len(v.Services))
	for i, x := range v.Services {
		services[i] = x.Export()
	}
	ports := make([]Port, len(v.Ports))
	for i, x := range v.Ports {
		ports[i] = x.Export()
	}
	return ConfigSpec{
		Config:    v.ToConfig(),
		Channels:  channels,
		Filters:   filters,
		Directors: dirs,
		Services:  services,
		Ports:     ports,
	}
}

type ConfigSpec struct {
	*config.Config //for overwriting the known config
	Channels       []Channel
	Services       []Service
	Filters        []Filter
	Directors      []Director
	Ports          []Port
}

func inactiveState(action Action) bool {
	switch action {
	case IGNORE, DISCARD:
		return true
	default:
		return false
	}
}

func Merge(v1, v2 *Validata, ignoreNewerDefinition bool) *Validata {
	//TODO use ignore newer definition
	v1.Channels = append(v1.Channels, v2.Channels...)
	v1.Filters = append(v1.Filters, v2.Filters...)
	v1.Directors = append(v1.Directors, v2.Directors...)
	v1.Services = append(v1.Services, v2.Services...)
	v1.Ports = append(v1.Ports, v2.Ports...)

	//channels
	for i, channel := range v1.Channels {
		for j := i + 1; j < len(v1.Channels); j++ {
			option := v1.Channels[j]
			if inactiveState(option.Action) {
				continue
			}
			if channel.Equals(option) {
				if ignoreNewerDefinition {
					option.Exclude()
				} else {
					channel.Action = DISCARD
				}
			}
		}
	}
	// repeat for other stuff
	// TODO switch to datastructure?!!

	for i, filter := range v1.Filters {
		for j := i + 1; j < len(v1.Filters); j++ {
			option := v1.Filters[j]
			if inactiveState(option.Action) {
				continue
			}
			if filter.Equals(option) {
				if ignoreNewerDefinition {
					option.Exclude()
				} else {
					filter.Action = DISCARD
				}
			}
		}
	}

	for i, dir := range v1.Directors {
		for j := i + 1; j < len(v1.Directors); j++ {
			option := v1.Directors[j]
			if inactiveState(option.Action) {
				continue
			}
			if dir.Equals(option) {
				if ignoreNewerDefinition {
					option.Exclude()
				} else {
					dir.Action = DISCARD
				}
			}
		}
	}

	for i, service := range v1.Services {
		for j := i + 1; j < len(v1.Services); j++ {
			option := v1.Services[j]
			if inactiveState(option.Action) {
				continue
			}
			if service.Equals(option) {
				if ignoreNewerDefinition {
					option.Exclude()
				} else {
					service.Action = DISCARD
				}
			}
		}
	}

	for i, port := range v1.Ports {
		for j := i + 1; j < len(v1.Ports); j++ {
			option := v1.Ports[j]
			if inactiveState(option.Action) {
				continue
			}
			if port.Equals(option) {
				if ignoreNewerDefinition {
					option.Exclude()
				} else {
					port.Action = DISCARD
				}
			}
		}
	}
	return v1
}

func (v Validator) Validate(current *Validata, update *config.Config) (*Validata, error) {
	log.Info("Validating configuration... Validating Channels, Filters, Directors, Services and Ports.")

	var prepared *Validata

	if current != nil && update != nil {
		if v.RemoveExisting {
			current.Prepare(DISCARD)
		} else {
			current.Prepare(KEEP)
		}
		next := newValidata(update)
		next.Prepare(CREATE)
		prepared = Merge(current, next, v.Replace)

	} else if current != nil {
		//this is no update
		return current, nil
	} else if update != nil {
		prepared = newValidata(update)
		prepared.Prepare(CREATE) // ussume it's new config
	} else {
		return nil, fmt.Errorf("No config supplied.")
	}

	return v.validate(prepared)
}

type Validator struct {
	Replace        bool
	RemoveExisting bool
}

//TODO split this function in a private validation, and a public callable function (allows different function signatures (e.g. one file, or two, etc.))
// Validate validates a single config file. do not use this for comparisons...
func (v Validator) validate(prepared *Validata) (*Validata, error) {

	// all items should self validate (e.g. is their private config o.k.)
	// this check ignores links to other objects
	prepared.SelfValidate()

	// Duplicates?
	// dont check for duplicatres here... This is for a single file

	// LINK: Filter --> channel
	// LINK: Filter --> Services (If any are defined)
	for _, filter := range prepared.GetFilters() {
		channel := prepared.GetChannel(filter.Target)
		if channel == nil {
			// ignore this filter, it won't write to anything. It's useless.
			log.Error("Could not find channel '%s' for filter", filter.Target)
			filter.Action = IGNORE
			continue
		}

		// LINK!
		channel.Filters = append(channel.Filters, filter)
		filter.channelData = channel
	}

	// check for channels with no filter (unused channels)
	for _, channel := range prepared.GetChannels() {
		if 0 == len(channel.Filters) {
			log.Error("No filters configured for channel '%s', type: '%s'", channel.Name, channel.Meta.Type)
			channel.Action = IGNORE
			continue
		}
	}

	// LINK: Service --> director
	// If a service cannot be linked to any director, it should not be used
	// if a service has a direc specified, but cannot be linked to it, ignore the service definition
	for _, service := range prepared.GetServices() {
		directorName := service.Meta.Director
		if "" == directorName {
			continue // no director set, do not check if director exists
		}

		d := prepared.GetDirector(directorName)
		if nil == d {
			log.Error("No director of type '%s' found for service '%s'", directorName, service.Name)
			service.Action = IGNORE
			continue //ignore this service...
		}
		// LINK!
		service.directorData = d
		d.Services = append(d.Services, service)
	}

	// check for unused directors
	for _, d := range prepared.GetDirectors() {
		if 0 == len(d.Services) {
			log.Error("Director '%s' unused, excluding it from config", d.Meta.Type)
			d.Action = IGNORE
			continue
		}
	}

	// LINK: Filter --> Services
	// check if services exist (non-blockingfatal for a channel... )
	// filters with no services are excluded
	for _, filter := range prepared.GetFilters() {
		// is this filter filtering services?
		if len(filter.Meta.Services) == 0 {
			//no service filtering
			continue
		}
		for _, name := range filter.Meta.Services {
			service := prepared.GetService(name)
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
			filter.Action = IGNORE
		}
	}

	// CHECK: all ports unique?
	ports := prepared.GetPorts()
	for i := 0; i < len(ports)-1; i++ {
		porti := ports[i]

		//TODO check if this code is obsolete
		//	if porti.Action == IGNORE {
		//		continue
		//}
		for j := i + 1; j < len(ports); j++ {
			portj := ports[j]
			//TODO check if code is obsolete
			//if portj.Action == IGNORE {
			//	continue
			//}
			if overlap := porti.Overlapping(portj); len(overlap) != 0 {
				prts := []string{}
				for _, x := range overlap {
					prts = append(prts, fmt.Sprintf("%s%s", x.Network(), x.String()))
				}
				log.Error("Port(s) already defined / in use. Was it defined twice? [%s]", strings.Join(prts, ";"))
				portj.Action = IGNORE
			}
		}
	}

	// LINK: Port --> Service
	// matches services to port IF the services have not been excluded for config errors
	for _, port := range prepared.GetPorts() {

		s := port.Meta.Services
		//log.Infof("Checking port %s", port.Dump())
		if 0 == len(s) {
			log.Error("No services configured for port with config: %s", port.Dump())
			port.Action = IGNORE
			continue
		}

		for _, serviceName := range s {
			service := prepared.GetService(serviceName)
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
			log.Error("Port %s has no valid services, wanted: %v. Did a service fail to configure?", port.Name(), port.Meta.Services)
			port.Action = IGNORE
			continue
		}
	}

	// Check if all services are assinged to ports
	for _, service := range prepared.GetServices() {
		if 0 == len(service.Ports) {
			log.Error("No ports configured for service '%s'", service.Name)
			service.Action = IGNORE
		}
	}

	//TODO: for compare: Check for links to current config -- NOT HERE
	prepared.UnusedConfig()

	return prepared, nil
}
