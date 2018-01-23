package statscollector

import (
	"strings"
	"sync"
	"time"

	"github.com/contiv/vpp/plugins/contiv"
	"github.com/golang/protobuf/proto"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/flavors/local"
	prometheusplugin "github.com/ligato/cn-infra/rpc/prometheus"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/model/interfaces"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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

// Plugin collects the statistics from vpp interfaces and publishes them to prometheus.
type Plugin struct {
	Deps
	sync.Mutex
	ifStats   map[string]*stats
	closeCh   chan interface{}
	gaugeVecs map[string]*prometheus.GaugeVec
}

type stats struct {
	podName      string
	podNamespace string
	data         *interfaces.InterfacesState_Interface
	metrics      map[string]prometheus.Gauge
}

// Deps groups the dependencies of the Plugin.
type Deps struct {
	local.PluginInfraDeps

	// Contiv plugin is used to lookup pod related to interfaces statistics
	Contiv contiv.API

	// Prometheus plugin used to stream statistics
	Prometheus prometheusplugin.API
}

// Init initializes the plugin resources
func (p *Plugin) Init() error {
	p.closeCh = make(chan interface{})
	p.ifStats = map[string]*stats{}
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

	// TODO watch containerIDX and remove gauges of pods that have been deleted

	go p.PrintStats()

	return nil
}

// Close cleans up the plugin resources
func (p *Plugin) Close() error {
	close(p.closeCh)
	return nil
}

// PrintStats dumps stats to log
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

	if strings.HasPrefix(key, interfaces.InterfaceStateKeyPrefix()) {
		var (
			err            error
			entry          *stats
			podName, podNs string
			found          bool
		)
		const contivSystemInterfacePlaceholder = "--"
		if st, ok := data.(*interfaces.InterfacesState_Interface); ok {
			entry, found = p.ifStats[key]
			// interface is associated with a pod and we're already streaming its statistics
			if found && entry.podName != "" {
				entry.data = st
				p.ifStats[key] = entry
				p.updatePrometheusStats(entry)
			} else {
				// adding stats for new interface
				contivInterface := p.isContivSystemInterface(st.Name)
				if contivInterface {
					podName = contivSystemInterfacePlaceholder
					podNs = contivSystemInterfacePlaceholder
				} else {
					podNs, podName, found = p.Contiv.GetPodByIf(st.Name)
				}

				if found || contivInterface {
					entry = &stats{
						podName:      podName,
						podNamespace: podNs,
						data:         st,
						metrics:      map[string]prometheus.Gauge{},
					}

					for k, vec := range p.gaugeVecs {
						entry.metrics[k], err = vec.GetMetricWith(prometheus.Labels{
							podNameLabel:       podName,
							podNamespaceLabel:  podNs,
							interfaceNameLabel: st.Name,
						})
						if err != nil {
							p.Log.Error(err)
						}
					}
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
	for _, n := range []string{"afpacket-vpp2", "vpp2", "vxlanBVI", "loopbackNIC"} {
		if n == ifName {
			return true
		}
	}
	return false
}
