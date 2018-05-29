package supervisor

import (
  "context"
  "fmt"
  "net"
  "net/http"

  "github.com/kolo/xmlrpc"
)

type RunCode int

const (
  STATE_SHUTDOWN   RunCode = iota - 1 // -1: In process of shutting down.
  STATE_RESTARTING                    //  0: In the process of restarting.
  STATE_RUNNING                       //  1: Is working normally.
  STATE_FATAL                         //  2: Has experienced a serious error.
)

type ProcessInfo struct {
  Name          string `xmlrpc:"name"`
  Group         string `xmlrpc:"group"`
  Description   string `xmlrpc:"description"`
  Start         int64  `xmlrpc:"start"`
  Stop          int64  `xmlrpc:"stop"`
  Now           int64  `xmlrpc:"now"`
  State         int64  `xmlrpc:"state"`
  StateName     string `xmlrpc:"statename"`
  SpawnErr      string `xmlrpc:"spawnerr"`
  ExitStatus    int64  `xmlrpc:"exitstatus"`
  StdoutLogFile string `xmlrpc:"stdout_logfile"`
  StderrLogFile string `xmlrpc:"stderr_logfile"`
  Pid           int64  `xmlrpc:"pid"`
}

type State struct {
  Code RunCode `xmlrpc:"statecode"`
  Name string  `xmlrpc:"statename"`
}

type Client struct {
  addr string
  port int
  user string
  pass string
}

func New(addr string, port int, username, password string) Client {
  return Client{
    addr: addr,
    port: port,
    user: username,
    pass: password,
  }
}

func (c Client) isUnixDomain() bool {
  return c.addr != "" && c.addr[0] == '/'
}

func (c Client) url() string {
  if c.isUnixDomain() {
    // unix-domain socket connection
    return fmt.Sprintf("http://%s:%s@unix/RPC2", c.user, c.pass)
  } else {
    // TCP connection
    return fmt.Sprintf("http://%s:%s@%s:%d/RPC2", c.user, c.pass, c.addr, c.port)
  }
}

func (c Client) makeRequest(method string, args, result interface{}) error {
  var transport *http.Transport

  if c.isUnixDomain() {
    // unix-domain socket connection
    transport = &http.Transport{
      DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
        return net.Dial("unix", c.addr)
      },
    }
  }

  xc, err := xmlrpc.NewClient(c.url(), transport)
  if err != nil {
    return err
  }
  defer xc.Close()

  err = xc.Call(method, args, result)
  if err != nil {
    return err
  }
  return nil
}
