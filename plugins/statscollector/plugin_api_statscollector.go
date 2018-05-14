package statscollector

// API defines API of the stats collector plugin. Currently it only allows registering of a gauge.
type API interface {
	// RegisterGaugeFunc registers a new gauge with specific name, help string and valueFunc to report status when invoked.
	RegisterGaugeFunc(name string, help string, valueFunc func() float64)
}
