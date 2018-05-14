package statscollector

type API interface {
	RegisterGauge(name string, help string, valueFunc func() float64)
}
