package statscollector

import (
	"strings"
	"sync"
	"time"

	"github.com/contiv/vpp/plugins/contiv"
	"github.com/gogo/protobuf/proto"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/infra"
	prometheusplugin "github.com/ligato/cn-infra/rpc/prometheus"
	"github.com/ligato/cn-infra/servicelabel"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/contiv/vpp/plugins/podmanager"
	controller "github.com/contiv/vpp/plugins/controller/api"
)

const (
	// path where the statistics are exposed
	prometheusStatsPath = "/stats"

	podNameLabel       = "podName"
	podNamespaceLabel  = "podNamespace"
	interfaceNameLabel = "interfaceName"
	nodeLabel          = "node"

	inPacketsMetric       = "inPackets"
	outPacketsMetric      = "outPackets"
	inBytesMetric         = "inBytes"
	outBytesMetric        = "outBytes"
	dropPacketsMetric     = "dropPackets"
	puntPacketsMetric     = "puntPackets"
	ipv4PacketsMetric     = "ipv4Packets"
	ipv6PacketsMetric     = "ipv6Packets"
	inNobufPacketsMetric  = "inNobufPackets"
	inMissPacketsMetric   = "inMissPackets"
	inErrorPacketsMetric  = "inErrorPackets"
	outErrorPacketsMetric = "outErrorPackets"
)

var systemIfNames = []string{"afpacket-vpp2", "vpp2", "tap-vpp2", "vxlanBVI", "loopbackNIC", "GigabitEthernet"}

// Plugin collects the statistics from vpp interfaces and publishes them to prometheus.
type Plugin struct {
	Deps
	sync.Mutex
	ifStats   map[string]*stats
	closeCh   chan interface{}
	gaugeVecs map[string]*prometheus.GaugeVec
	podIfs    map[string] /*pod namespace*/ map[string] /*pod name*/ []string /*stats keys*/
}

type stats struct {
	podName      string
	podNamespace string
	data         *interfaces.InterfaceState
	metrics      map[string]prometheus.Gauge
}

// Deps groups the dependencies of the Plugin.
type Deps struct {
	infra.PluginDeps
	ServiceLabel servicelabel.ReaderAPI
	// Contiv plugin is used to lookup pod related to interfaces statistics
	Contiv contiv.API

	// Prometheus plugin used to stream statistics
	Prometheus prometheusplugin.API
}

// Init initializes the plugin resources
func (p *Plugin) Init() error {
	p.closeCh = make(chan interface{})
	p.ifStats = map[string]*stats{}
	p.podIfs = map[string]map[string][]string{}
	p.gaugeVecs = map[string]*prometheus.GaugeVec{}

	if p.Prometheus != nil {
		// create new registry for statistics
		err := p.Prometheus.NewRegistry(prometheusStatsPath, promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError, ErrorLog: p.Log})
		if err != nil {
			return err
		}

		// initialize gauge vectors for statistics
		for _, statItem := range [][2]string{
			{inPacketsMetric, "Number of received packets for interface"},
			{outPacketsMetric, "Number of transmitted packets for interface"},
			{inBytesMetric, "Number of received bytes for interface"},
			{outBytesMetric, "Number of transmitted bytes for interface"},
			{dropPacketsMetric, "Number of dropped packets for interface"},
			{puntPacketsMetric, "Number of punt packets for interface"},
			{ipv4PacketsMetric, "Number of ipv4 packets for interface"},
			{ipv6PacketsMetric, "Number of ipv6 packets for interface"},
			{inNobufPacketsMetric, "Number of received packets ??? for interface"}, // TODO describe metric
			{inMissPacketsMetric, "Number of missed packets for interface"},
			{inErrorPacketsMetric, "Number of received packets with error for interface"},
			{outErrorPacketsMetric, "Number of transmitted packets with error for interface"},
		} {

			name := statItem[0]
			help := statItem[1]

			p.gaugeVecs[name] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Name: name,
				Help: help,
				ConstLabels: prometheus.Labels{
					nodeLabel: p.ServiceLabel.GetAgentLabel(),
				},
			}, []string{podNameLabel, podNamespaceLabel, interfaceNameLabel})

		}

		// register created vectors to prometheus
		for name, metric := range p.gaugeVecs {
			err = p.Prometheus.Register(prometheusStatsPath, metric)
			if err != nil {
				p.Log.Errorf("failed to register %v metric %v", name, err)
				return err
			}
		}

	}

	go p.PrintStats()

	return nil
}

// HandlesEvent selects DeletePod events.
func (p *Plugin) HandlesEvent(event controller.Event) bool {
	if _, isDeletePod := event.(*podmanager.DeletePod); isDeletePod {
		return true
	}

	// unhandled event
	return false
}

// Resync is NOOP - statscollector does not support re-synchronization.
func (p *Plugin) Resync(controller.Event, controller.KubeStateData, int, controller.ResyncOperations) error {
	return nil
}

// Update is called for:
//   - AddPod and DeletePod
//   - NodeUpdate for other nodes
//   - Shutdown event
func (p *Plugin) Update(event controller.Event, _ controller.UpdateOperations) (changeDescription string, err error) {
	deletePod := event.(*podmanager.DeletePod)

	nsmap, exists := p.podIfs[deletePod.Pod.Namespace]
	if !exists {
		return "", nil
	}
	ifs, exists := nsmap[deletePod.Pod.Name]
	if !exists {
		return "", nil
	}
	for _, key := range ifs {
		entry, exists := p.ifStats[key]
		if exists && entry != nil {
			// remove gauge with corresponding labels from each vector
			for _, vec := range p.gaugeVecs {
				vec.Delete(prometheus.Labels{
					podNameLabel:       entry.podName,
					podNamespaceLabel:  entry.podNamespace,
					interfaceNameLabel: entry.data.Name,
				})
				if err != nil {
					p.Log.Error(err)
				}
			}

		}
		delete(p.ifStats, key)
	}

	return "removed interface stats", nil
}

// Revert is NOOP - only BestEffor DeletePod event is handled.
func (p *Plugin) Revert(controller.Event) error {
	return nil
}

// Close cleans up the plugin resources
func (p *Plugin) Close() error {
	close(p.closeCh)
	return nil
}

// PrintStats periodically dumps stats to log
func (p *Plugin) PrintStats() {
	for {
		select {
		case <-p.closeCh:
			return
		case <-time.After(10 * time.Second):
			p.Lock()
			for _, v := range p.ifStats {
				p.Log.Debugf("%v %v %v %+v", v.data.Name, v.podName, v.podNamespace, *v.data.Statistics)
			}
			p.Unlock()
		}
	}
}

// Put updates the statistics for the given key
func (p *Plugin) Put(key string, data proto.Message, opts ...datasync.PutOption) error {
	p.Lock()
	defer p.Unlock()

	p.Log.Debugf("Statistic data with key %v received", key)
	if strings.HasPrefix(key, interfaces.StatePrefix) {
		var (
			entry *stats
			found bool
		)
		if st, ok := data.(*interfaces.InterfaceState); ok {
			entry, found = p.ifStats[key]
			if found && entry.podName != "" {
				// interface is associated with a pod and we're already streaming its statistics
				entry.data = st
				p.ifStats[key] = entry
				p.updatePrometheusStats(entry)
			} else {
				// adding stats for new interface
				var created bool
				entry, created = p.addNewEntry(key, st)
				if created {
					p.ifStats[key] = entry
					p.updatePrometheusStats(entry)
				}
			}
		} else {
			p.Log.Warn("Unable to decode received stats")
		}
	}

	return nil
}

// RegisterGaugeFunc registers a new gauge with specific name, help string and valueFunc to report status when invoked.
func (p *Plugin) RegisterGaugeFunc(name string, help string, valueFunc func() float64) {
	p.Lock()
	defer p.Unlock()

	p.Log.Debugf("Registering new gauge: %s", name)

	if p.Prometheus != nil {
		promLables := prometheus.Labels{
			nodeLabel: p.ServiceLabel.GetAgentLabel(),
		}

		p.Prometheus.RegisterGaugeFunc(prometheusStatsPath, "", "", name, help, promLables, valueFunc)
	}
}

func (p *Plugin) addNewEntry(key string, data *interfaces.InterfaceState) (newEntry *stats, created bool) {
	var (
		err            error
		entry          *stats
		podName, podNs string
		found          bool
	)
	const contivSystemInterfacePlaceholder = "--"

	contivInterface := p.isContivSystemInterface(data.Name)
	if contivInterface {
		podName = contivSystemInterfacePlaceholder
		podNs = contivSystemInterfacePlaceholder
	} else {
		podNs, podName, found = p.Contiv.GetPodByIf(data.Name)
	}

	if found {
		// add entry into pod - interface mapping, in order to allow
		// deletion of metrics when a pod is undeployed
		nsmap, exists := p.podIfs[podNs]
		if !exists {
			nsmap = map[string][]string{}
			p.podIfs[podNs] = nsmap
		}

		nsmap[podName] = append(nsmap[podName], key)
	}

	if found || contivInterface {
		entry = &stats{
			podName:      podName,
			podNamespace: podNs,
			data:         data,
			metrics:      map[string]prometheus.Gauge{},
		}

		// add gauges with corresponding labels into vectors
		for k, vec := range p.gaugeVecs {
			entry.metrics[k], err = vec.GetMetricWith(prometheus.Labels{
				podNameLabel:       podName,
				podNamespaceLabel:  podNs,
				interfaceNameLabel: data.Name,
			})
			if err != nil {
				p.Log.Error(err)
			}
		}
		return entry, true
	}
	return nil, false
}

// updatePrometheusStats publishes the statistics for the given interfaces into prometheus
func (p *Plugin) updatePrometheusStats(entry *stats) {
	if inPacket, found := entry.metrics[inPacketsMetric]; found && inPacket != nil {
		inPacket.Set(float64(entry.data.Statistics.InPackets))
	}
	if outPacket, found := entry.metrics[outPacketsMetric]; found && outPacket != nil {
		outPacket.Set(float64(entry.data.Statistics.OutPackets))
	}
	if inBytes, found := entry.metrics[inBytesMetric]; found && inBytes != nil {
		inBytes.Set(float64(entry.data.Statistics.InBytes))
	}
	if outBytes, found := entry.metrics[outBytesMetric]; found && outBytes != nil {
		outBytes.Set(float64(entry.data.Statistics.OutBytes))
	}
	if dropPacket, found := entry.metrics[dropPacketsMetric]; found && dropPacket != nil {
		dropPacket.Set(float64(entry.data.Statistics.DropPackets))
	}
	if puntPacket, found := entry.metrics[puntPacketsMetric]; found && puntPacket != nil {
		puntPacket.Set(float64(entry.data.Statistics.PuntPackets))
	}
	if ipv4Packet, found := entry.metrics[ipv4PacketsMetric]; found && ipv4Packet != nil {
		ipv4Packet.Set(float64(entry.data.Statistics.Ipv4Packets))
	}
	if ipv6Packet, found := entry.metrics[ipv6PacketsMetric]; found && ipv6Packet != nil {
		ipv6Packet.Set(float64(entry.data.Statistics.Ipv6Packets))
	}
	if inNoBufPacket, found := entry.metrics[inNobufPacketsMetric]; found && inNoBufPacket != nil {
		inNoBufPacket.Set(float64(entry.data.Statistics.InNobufPackets))
	}
	if inMissPacket, found := entry.metrics[inMissPacketsMetric]; found && inMissPacket != nil {
		inMissPacket.Set(float64(entry.data.Statistics.InMissPackets))
	}
	if inErrorPacket, found := entry.metrics[inErrorPacketsMetric]; found && inErrorPacket != nil {
		inErrorPacket.Set(float64(entry.data.Statistics.InErrorPackets))
	}
	if outErrorPacket, found := entry.metrics[outErrorPacketsMetric]; found && outErrorPacket != nil {
		outErrorPacket.Set(float64(entry.data.Statistics.OutErrorPackets))
	}
}

// isContivSystemInterface returns true if given interface name is not associated
// with a pod (e.g. interface that interconnect vpp and host stack), otherwise false
func (p *Plugin) isContivSystemInterface(ifName string) bool {
	for _, n := range systemIfNames {
		if strings.HasPrefix(ifName, n) {
			return true
		}
	}
	return false
}
