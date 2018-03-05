package supervisor

const (
	GROUPS_ADDED	=	"PROCESS_GROUPS_ADDED"
	GROUPS_CHANGED	=	"PROCESS_GROUPS_CHANGED"
	GROUPS_REMOVED	=	"PROCESS_GROUPS_REMOVED"
)
// Get info about a specific process
func (c Client) GetProcessInfo(name string) (*ProcessInfo, error) {
	result := &ProcessInfo{}
	err := c.makeRequest("supervisor.getProcessInfo", []interface{}{name}, &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Get info about all processes
func (c Client) GetAllProcessInfo() ([]ProcessInfo, error) {
	var result []ProcessInfo
	err := c.makeRequest("supervisor.getAllProcessInfo", nil, &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Start a process
func (c Client) StartProcess(name string, wait bool) (bool, error) {
	var result bool
	err := c.makeRequest("supervisor.startProcess", []interface{}{name, wait}, &result)
	if err != nil {
		return result, err
	}
	return result, nil
}

// Start all processes listed in the group specified
func (c Client) StartProcessGroup(name string, wait bool) ([]ProcessInfo, error) {
	var result []ProcessInfo
	err := c.makeRequest("supervisor.startProcessGroup", []interface{}{name, wait}, &result)
	if err != nil {
		return result, err
	}
	return result, nil
}

// Start all processes listed in the configuration file
func (c Client) StartAllProcesses(wait bool) ([]ProcessInfo, error) {
	var result []ProcessInfo
	err := c.makeRequest("supervisor.startAllProcesses", wait, &result)
	if err != nil {
		return result, err
	}
	return result, nil
}

// Stop a process
func (c Client) StopProcess(name string, wait bool) (bool, error) {
	var result bool
	err := c.makeRequest("supervisor.stopProcess", []interface{}{name, wait}, &result)
	if err != nil {
		return result, err
	}
	return result, nil
}

// Stop all processes listed in the group specified
func (c Client) StopProcessGroup(name string, wait bool) ([]ProcessInfo, error) {
	var result []ProcessInfo
	err := c.makeRequest("supervisor.stopProcessGroup", []interface{}{name, wait}, &result)
	if err != nil {
		return result, err
	}
	return result, nil
}

// Stop all processes listed in the configuration file
func (c Client) StopAllProcesses(wait bool) ([]ProcessInfo, error) {
	var result []ProcessInfo
	err := c.makeRequest("supervisor.stopAllProcesses", wait, &result)
	if err != nil {
		return result, err
	}
	return result, nil
}

// Send an arbitrary UNIX signal to the process specified
func (c Client) SignalProcess(name string, signal int) ([]*ProcessInfo, error) { return nil, nil }

// Send an arbitrary UNIX signal to all process in the group specified
func (c Client) SignalProcessGroup(name string, signal int) ([]*ProcessInfo, error) { return nil, nil }

// Send an arbitrary UNIX signal to all processes listed in the configuration file
func (c Client) SignalAllProcesses(signal int) ([]*ProcessInfo, error) { return nil, nil }

// Send a string of characters to the STDIN of the specified process
func (c Client) SendProcessStdin(name, chars string) error { return nil }

// Send an event that will be received by any event listener subprocesses
// subscribing to the 'RemoteCommunicationEvent'
func (c Client) SendRemoteCommEvent(t, data string) error { return nil }

// Reload the configuration ( supervisorctl reread )
func (c Client) ReloadConfig() (map[string][]string, error) {
	result1 := make([][][]string, 0)
	result2 := make(map[string][]string, 0)

	err := c.makeRequest("supervisor.reloadConfig", nil, &result1)

	if err != nil {
		return nil, err
	}

	result2[GROUPS_ADDED] = result1[0][0]
	result2[GROUPS_CHANGED] = result1[0][1]
	result2[GROUPS_REMOVED] = result1[0][2]

	return result2, nil
}

// Alternative for supervisorctl update
func (c Client) Update() error {
	data, err := c.ReloadConfig()

	if err != nil {
		return err
	}

	start := append(data[GROUPS_ADDED], data[GROUPS_CHANGED]...)
	stop := append(data[GROUPS_CHANGED], data[GROUPS_REMOVED]...)

	for _, name := range stop {
		if _, err := c.StopProcessGroup(name, true); err != nil {
			return err
		}

		if _, err := c.RemoveProcessGroup(name); err != nil {
			return err
		}
	}

	for _, name := range start {
		if _, err := c.AddProcessGroup(name); err != nil {
			return err
		}
	}

	return nil
}

// Update the config for a running process from the configuration file
func (c Client) AddProcessGroup(name string) (bool, error) {
	var result bool
	err := c.makeRequest("supervisor.addProcessGroup", name, &result)
	if err != nil {
		return result, err
	}
	return result, nil
}

// Remove a stopped process group from the active configuration
func (c Client) RemoveProcessGroup(name string) (bool, error) {
	var result bool
	err := c.makeRequest("supervisor.removeProcessGroup", name, &result)
	if err != nil {
		return result, err
	}
	return result, nil
}
