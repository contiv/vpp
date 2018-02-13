package supervisor

// Returns the version of the RPC API used by supervisord
func (c Client) ApiVersion() (string, error) {
	var result string
	err := c.makeRequest("supervisor.getAPIVersion", nil, &result)
	if err != nil {
		return "", err
	}
	return result, nil
}

// Return the version of the supervisor package in use by supervisord
func (c Client) SupervisorVersion() (string, error) {
	var result string
	err := c.makeRequest("supervisor.getSupervisorVersion", nil, &result)
	if err != nil {
		return "", err
	}
	return result, nil
}

// Result identifying string of supervisord
func (c Client) Identification() (string, error) {
	var result string
	err := c.makeRequest("supervisor.getIdentification", nil, &result)
	if err != nil {
		return "", err
	}
	return result, nil
}

// Return current state of supervisord as a struct
func (c Client) State() (*State, error) {
	result := &State{}
	err := c.makeRequest("supervisor.getState", nil, &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Return the PID of supervisord
func (c Client) Pid() (int64, error) {
	var result int64
	err := c.makeRequest("supervisor.getPID", nil, &result)
	if err != nil {
		return 0, err
	}
	return result, nil
}

// Read from the main supervisord log.
func (c Client) ReadLog(offset, length int) (string, error) {
	var result string
	err := c.makeRequest("supervisor.readLog", []interface{}{offset, length}, &result)
	if err != nil {
		return "", err
	}
	return result, nil
}

// Clear the main log file
func (c Client) Clearlog() error {
	return c.makeRequest("supervisor.clearLog", nil, nil)
}

// Shutdown the supervisor process
func (c Client) Shutdown() error {
	return c.makeRequest("supervisor.shutdown", nil, nil)
}

// Restart the supervisor process
func (c Client) Restart() error {
	return c.makeRequest("supervisor.restart", nil, nil)
}
