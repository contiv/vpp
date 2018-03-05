package supervisor

// Read from the stdout for specified process
func (c Client) ReadProcessStdout(name string, offset, length int) (string, error) {
	var result string
	err := c.makeRequest("supervisor.readProcessStdoutLog", []interface{}{name, offset, length}, &result)
	if err != nil {
		return "", err
	}
	return result, nil
}

// Read from the stderr for the specified process
func (c Client) ReadProcessStderr(name string, offset, length int) (string, error) {
	var result string
	err := c.makeRequest("supervisor.readProcessStderrLog", []interface{}{name, offset, length}, &result)
	if err != nil {
		return "", err
	}
	return result, nil
}

// Provides a more efficient way to tail the stdout log
func (c Client) TailProcessStdout(name string, offset, length int) (string, error) {
	var result string
	err := c.makeRequest("supervisor.tailProcessStdoutLog", []interface{}{name, offset, length}, &result)
	if err != nil {
		return "", err
	}
	return result, nil
}

// Provides a more efficient way to tail the stderr log
func (c Client) TailProcessStderr(name string, offset, length int) (string, error) {
	var result string
	err := c.makeRequest("supervisor.tailProcessStderrLog", []interface{}{name, offset, length}, &result)
	if err != nil {
		return "", err
	}
	return result, nil
}

// Clear the stdout and stderr logs for the specified process and reopen them
func (c Client) ClearProcessLogs(name string) error {
	return c.makeRequest("supervisor.clearProcessLogs", []interface{}{name}, nil)
}

// Clear all process log files
func (c Client) ClearAllProcessLogs() error {
	return c.makeRequest("supervisor.clearAllProcessLogs", nil, nil)
}
