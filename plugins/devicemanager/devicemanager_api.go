package devicemanager

import (
	"fmt"
	"strings"

	controller "github.com/contiv/vpp/plugins/controller/api"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
)

/********************************* Plugin API *********************************/

// API defines methods provided by the DeviceManager plugin for use by other plugins
// to query pod memif allocation info and release pod memif allocations.
type API interface {
	// GetPodMemifInfo returns info related to memif devices connected to the specified pod.
	GetPodMemifInfo(pod podmodel.ID) (info *MemifInfo, err error)
}

// MemifInfo holds memif-related information of a pod.
type MemifInfo struct {
	HostSocket      string
	ContainerSocket string
	Secret          string
}

// String describes MemifInfo structure with obfuscated secret content.
func (m *MemifInfo) String() string {
	return fmt.Sprintf("{HostSocket:%s ContainerSocket:%s Secret:%s}",
		m.HostSocket, m.ContainerSocket, strings.Repeat("*", len(m.Secret)))
}

/******************************* Allocate Device Event ********************************/

// AllocateDevice event is triggered when a container is requesting a device supported by contiv on this node.
type AllocateDevice struct {
	result chan error

	// input arguments (read by event handlers)
	DevicesIDs []string

	// output arguments (edited by event handlers)
	Envs        map[string]string
	Annotations map[string]string
	Mounts      []Mount
}

// Mount represents a host-to-container mount.
type Mount struct {
	HostPath      string
	ContainerPath string
}

// NewAllocateDeviceEvent is constructor for AllocateDevice event.
func NewAllocateDeviceEvent(devicesIDs []string) *AllocateDevice {
	return &AllocateDevice{
		DevicesIDs: devicesIDs,
		result:     make(chan error, 1),
	}
}

// GetName returns name of the AllocateDevice event.
func (ev *AllocateDevice) GetName() string {
	return fmt.Sprintf("Allocate Device")
}

// String describes AllocateDevice event.
func (ev *AllocateDevice) String() string {
	return fmt.Sprintf("%s\n"+
		"* DevicesIDs: %v\n",
		ev.GetName(), ev.DevicesIDs)
}

// Method is Update.
func (ev *AllocateDevice) Method() controller.EventMethodType {
	return controller.Update
}

// TransactionType is RevertOnFailure.
func (ev *AllocateDevice) TransactionType() controller.UpdateTransactionType {
	return controller.RevertOnFailure
}

// Direction is forward.
func (ev *AllocateDevice) Direction() controller.UpdateDirectionType {
	return controller.Forward
}

// IsBlocking returns true.
func (ev *AllocateDevice) IsBlocking() bool {
	return true
}

// Done propagates error to the event producer.
func (ev *AllocateDevice) Done(err error) {
	ev.result <- err
	return
}

// Wait waits for the result of the AllocateDevice event.
func (ev *AllocateDevice) Wait() error {
	return <-ev.result
}
