package supervisor

import (
	"bufio"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
)

type Event string

const (
	EVENT_BASE                             Event = "EVENT"
	EVENT_PROCESS_STATE                          = "PROCESS_STATE"
	EVENT_PROCESS_STATE_STARTING                 = "PROCESS_STATE_STARTING"
	EVENT_PROCESS_STATE_RUNNING                  = "PROCESS_STATE_RUNNING"
	EVENT_PROCESS_STATE_BACKOFF                  = "PROCESS_STATE_BACKOFF"
	EVENT_PROCESS_STATE_STOPPING                 = "PROCESS_STATE_STOPPING"
	EVENT_PROCESS_STATE_EXITED                   = "PROCESS_STATE_EXITED"
	EVENT_PROCESS_STATE_STOPPED                  = "PROCESS_STATE_STOPPED"
	EVENT_PROCESS_STATE_FATAL                    = "PROCESS_STATE_FATAL"
	EVENT_PROCESS_STATE_UNKNOWN                  = "PROCESS_STATE_UNKNOWN"
	EVENT_REMOTE_COMMUNICATION                   = "REMOTE_COMMUNICATION"
	EVENT_PROCESS_LOG                            = "PROCESS_LOG"
	EVENT_PROCESS_LOG_STDOUT                     = "PROCESS_LOG_STDOUT"
	EVENT_PROCESS_LOG_STDERR                     = "PROCESS_LOG_STDERR"
	EVENT_PROCESS_COMMUNICATION                  = "PROCESS_COMMUNICATION"
	EVENT_PROCESS_COMMUNICATION_STDOUT           = "PROCESS_COMMUNICATION_STDOUT"
	EVENT_PROCESS_COMMUNICATION_STDERR           = "PROCESS_COMMUNICATION_STDERR"
	EVENT_SUPERVISOR_STATE_CHANGE                = "SUPERVISOR_STATE_CHANGE"
	EVENT_SUPERVISOR_STATE_CHANGE_RUNNING        = "SUPERVISOR_STATE_CHANGE_RUNNING"
	EVENT_SUPERVISOR_STATE_CHANGE_STOPPING       = "SUPERVISOR_STATE_CHANGE_STOPPING"
	EVENT_TICK                                   = "TICK"
	EVENT_TICK_5                                 = "TICK_5"
	EVENT_TICK_60                                = "TICK_60"
	EVENT_TICK_3600                              = "TICK_3600"
	EVENT_PROCESS_GROUP                          = "PROCESS_GROUP"
	EVENT_PROCESS_GROUP_ADDED                    = "PROCESS_GROUP_ADDED "
	EVENT_PROCESS_GROUP_REMOVED                  = "PROCESS_GROUP_REMOVED"
)

type EventMessage struct {
	Headers *HeaderToken
	Body    []byte
}

func NewEventMessage(headers *HeaderToken, body []byte) EventMessage {
	return EventMessage{
		Headers: headers,
		Body:    body,
	}
}

func (e EventMessage) String() string { return string(e.Body) }

func (e EventMessage) AsMap() map[string]string {
	data := make(map[string]string)

	body := strings.Split(strings.TrimSpace(e.String()), " ")
	for _, s := range body {
		t := strings.Split(s, ":")
		data[t[0]] = t[1]
	}
	return data
}

type HeaderToken struct {
	Version    string `token:"ver"`        // The event system protocol version.
	Server     string `token:"server"`     // The identifier of the supervisord sending the event.
	Serial     int    `token:"serial"`     // An integer assigned to each event.
	Pool       string `token:"pool"`       // The name of the event listener pool which generated this event.
	PoolSerial int    `token:"poolserial"` // An integer assigned to each event by the eventlistener pool which is being sent from.
	EventName  Event  `token:"eventname"`  // The specific event type name.
	Length     int    `token:"len"`        // An integer indicating the number of bytes in the event payload.
}

func NewHeaderToken(header string) (*HeaderToken, error) {
	headers := make(map[string]interface{})

	hs := strings.Split(strings.TrimSpace(header), " ")
	for _, h := range hs {
		t := strings.Split(h, ":")
		headers[t[0]] = t[1]
	}

	token := &HeaderToken{}
	if err := token.fillStruct(headers); err != nil {
		return nil, err
	}
	return token, nil
}

func (t *HeaderToken) fillStruct(m map[string]interface{}) error {
	var err error
	for k, v := range m {
		switch k {
		case "ver", "server", "pool":
			// String
			err = t.setField(k, v.(string))
		case "serial", "poolserial", "len":
			// Integer
			i, err := strconv.Atoi(v.(string))
			if err != nil {
				return err
			}
			err = t.setField(k, i)
		case "eventname":
			// Event type
			err = t.setField(k, Event(v.(string)))
		}
	}
	return err
}

func (t *HeaderToken) setField(name string, value interface{}) error {
	structValue := reflect.ValueOf(t).Elem()
	structType := reflect.TypeOf(t).Elem()

	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i)
		tag := field.Tag.Get("token")

		if tag == name {
			structFieldValue := structValue.FieldByName(field.Name)

			if !structFieldValue.CanSet() {
				return fmt.Errorf("Cannot set '%s' field value", name)
			}

			structFieldType := structFieldValue.Type()
			val := reflect.ValueOf(value)
			if structFieldType != val.Type() {
				return fmt.Errorf("Provided value type didn't match obj field type, got: '%s', expected: '%s'", structFieldType, val.Type())
			}

			structFieldValue.Set(val)
			return nil
		}
	}

	// Tag wasn't found, use field name
	structFieldValue := structValue.FieldByName(name)

	if !structFieldValue.IsValid() {
		return fmt.Errorf("No such field: '%s' in obj", name)
	}

	if !structFieldValue.CanSet() {
		return fmt.Errorf("Cannot set '%s' field valie", name)
	}

	structFieldType := structFieldValue.Type()
	val := reflect.ValueOf(value)
	if structFieldType != val.Type() {
		return fmt.Errorf("Provided value type didn't match obj field type")
	}

	structFieldValue.Set(val)
	return nil
}

type Listener struct {
	Stdin         *os.File
	Stdout        *os.File
	Stderr        *os.File
	processFilter []string
	eventFilter   []Event
	messages      chan EventMessage
}

func NewListener() *Listener {
	return &Listener{
		Stdin:         os.Stdin,
		Stdout:        os.Stdout,
		Stderr:        os.Stderr,
		processFilter: make([]string, 0),
		eventFilter:   make([]Event, 0),
		messages:      make(chan EventMessage, 1000),
	}
}

func (l *Listener) Messages() chan EventMessage { return l.messages }

// Filter to specific process names
func (l *Listener) FilterProcesses(p []string) { l.processFilter = p }

// filter to specific event types
func (l *Listener) FilterEvents(e []Event) { l.eventFilter = e }

func (l *Listener) passesFilters(process string, event Event) bool {
	pfLen := len(l.processFilter)
	efLen := len(l.eventFilter)
	processPass := false
	eventPass := false

	if pfLen == 0 && efLen == 0 {
		// No filters set, everything is welcome
		return true
	}

	if pfLen > 0 {
		for _, pName := range l.processFilter {
			if pName == process {
				// Process is in the acceptable filters
				processPass = true
				break
			}
		}
	} else {
		// No filters set for processes
		processPass = true
	}

	if efLen > 0 {
		for _, fName := range l.eventFilter {
			if fName == event {
				// Event passes the filter
				eventPass = true
				break
			}
		}
	} else {
		// No filters for event types set
		eventPass = true
	}

	if processPass && eventPass {
		return true
	}
	return false
}

// Run this in a go-routine
func (l *Listener) Listen() {
	// Set up STDIN reader
	input := bufio.NewReader(l.Stdin)

	var line string
	var headers *HeaderToken

	for {
		// Transition from ACKNOWLEDGED to READY state
		l.Stdout.WriteString("READY\n")

		// Read header line and print it to stderr
		line, _ = input.ReadString('\n')
		l.Stderr.WriteString(line)

		//Build headers list from input
		headers, _ = NewHeaderToken(line)

		// Read in body based on the length provided by the header
		body := make([]byte, headers.Length)
		input.Read(body)
		l.Stderr.WriteString(fmt.Sprintf("body (%s)\n", string(body)))

		// Push message into queue if they pass the specified filters
		msg := NewEventMessage(headers, body)
		if l.passesFilters(msg.AsMap()["processname"], headers.EventName) {
			l.messages <- msg
		}

		// Transition from READY to ACKNOWLEDGED state
		l.Stdout.WriteString("RESULT 2\nOK")
	}
}
