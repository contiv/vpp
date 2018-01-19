package statscollector

import (
	"github.com/contiv/vpp/plugins/contiv"
	"github.com/golang/protobuf/proto"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/flavors/local"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/model/interfaces"
	"strings"
	"sync"
	"time"
)

// Plugin collects the statistics from vpp interfaces and publishes them to prometheus.
type Plugin struct {
	Deps
	sync.Mutex
	ifStats map[string]stats
	closeCh chan interface{}
}

type stats struct {
	podName      string
	podNamespace string
	data         *interfaces.InterfacesState_Interface
}

// Deps groups the dependencies of the Plugin.
type Deps struct {
	local.PluginInfraDeps

	// Contiv plugin is used to lookup pod related to interfaces statistics
	Contiv contiv.API

	//TODO: prometheus plugin
}

// Init intializes the plugin resources
func (p *Plugin) Init() error {
	p.closeCh = make(chan interface{})
	p.ifStats = map[string]stats{}
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
				p.Log.Infof("%v %v %v %+v", v.data.Name, v.podName, v.podNamespace, *v.data.Statistics)
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
		if st, ok := data.(*interfaces.InterfacesState_Interface); ok {
			existingVal, found := p.ifStats[key]
			if found && existingVal.podName != "" {
				existingVal.data = st
				p.ifStats[key] = existingVal
			} else {
				podNs, podName, _ := p.Contiv.GetPodByIf(st.Name)
				p.ifStats[key] = stats{
					podName:      podName,
					podNamespace: podNs,
					data:         st,
				}
			}

			// TODO: publish to prometheus
		} else {
			p.Log.Warn("Unable to decode received stats")
		}
	}

	return nil
}
