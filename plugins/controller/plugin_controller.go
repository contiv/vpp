// Copyright (c) 2018 Cisco and/or its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import (
	"context"
	"errors"
	"sync"
	"time"
	"fmt"
	"strings"
	"strconv"

	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/health/statuscheck"
	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/rpc/rest"
	"github.com/ligato/cn-infra/servicelabel"

	"github.com/contiv/vpp/plugins/controller/api"
	scheduler "github.com/ligato/vpp-agent/plugins/kvscheduler/api"
)

const (
	// by default, dbwatcher waits one second for connection to remoteDB
	// to establish before falling back to local DB resync.
	defaultDelayLocalResync = time.Second

	// by default, Controller will report error to status check if it does not
	// receive startup DBResync event within the first minute of runtime.
	defaultStartupResyncDeadline = 1 * time.Minute

	// by default, remote DB connection is probed every 3 seconds (with one GetValue).
	defaultRemoteDBProbingInterval = 3 * time.Second
)

// Controller implements single event loop for Contiv.
//
// Events are represented by instances of the api.Event interface. A new event
// can be pushed into the loop for processing via the PushEvent method
// from the api.EventLoop interface, implemented by the Controller plugin.
//
// For a plugin to become a handler for one or more events, it has to implement
// the api.EventHandler interface. The set of event handlers is passed to Controller
// via EventHandlers attribute from Deps. The order of event handlers in the array
// matters - if handler B depends on A, i.e. A has to handle *any* event before B
// does, then A should precede B in the array. Cyclic dependencies are not allowed.
// Events then flow through the event handlers either in the forward or reverse
// order, based on the event direction (api.UpdateEvent.Direction(), "Forward" for
// Resync) and the event processing stage:
//  * "Forward" event, Update/Resync stage: forward iteration
//  * "Reverse" event, Update stage: backward iteration
//  * "Forward" event, Revert stage: backward iteration
//  * "Reverse" event, Revert stage: forward iteration
//
// For every event, the controller approaches a given handler first by checking
// if the handler is actually interested in the event using the method:
// api.EventHandler.HandlesEvent().
// Then, based on the event Method (api.Event.Method), it calls either Resync or
// Update method of the handler. The handler may update its internal state but
// for Update/RevertOnFailure (api.UpdateEvent.TransactionType) events it also
// has to be prepared to revert the changes (but only for that iteration of the
// event loop).
//
// The handler may return error from Update/Resync wrapped in either:
//  * api.FatalError to signal that the agent should be terminated
//    (and restarted by k8s), or
//  * api.AbortEventError to signal that the processing of the event should not
//    continue and a resync is needed.
// Non-fatal, non-abort error signals the controller that something is wrong and
// a resync is needed, but if the transaction is of type BestEffort, then
// the current event processing will continue.
//
// The handler is also provided with Update/Resync transaction for re-synchronizing
// or applying changes to VPP/Linux network configuration. Transactional errors
// are treated as non-fatal.
// If Update/RevertOnFailure event handling fails with non-fatal error, handlers
// that already reacted to the event will be asked in the reverse order to Revert
// any internal changes via method api.EventHandler.Revert().
//
// Processing of a given event is finalized by calling the api.Event.Done(error)
// method. The method can be used for example to deliver the return value back
// to the sender of the event.
type Controller struct {
	Deps

	config *Config

	dbWatcher     *dbWatcher
	kubeStateData api.KubeStateData

	revEventHandlers   []api.EventHandler
	eventQueue         chan api.Event
	delayedEvents      []api.Event
	startupResyncCheck chan struct{}

	resyncCount  int
	evSeqNum     uint64
	eventHistory []*EventRecord

	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

// Deps lists dependencies of the Controller.
type Deps struct {
	infra.PluginDeps

	Scheduler    scheduler.KVScheduler
	StatusCheck  statuscheck.PluginStatusWriter
	ServiceLabel servicelabel.ReaderAPI
	HTTPHandlers rest.HTTPHandlers  // TODO: REST for event history

	EventHandlers []api.EventHandler

	LocalDB     keyval.KvProtoPlugin
	RemoteDB    keyval.KvProtoPlugin
	DBResources []*api.DBResource
}

// Config holds the Controller configuration.
type Config struct {
	DelayLocalResync        time.Duration `json:"delay-local-resync"`
	StartupResyncDeadline   time.Duration `json:"startup-resync-deadline"`
	RemoteDBProbingInterval time.Duration `json:"remotedb-probing-interval"`
}

// EventRecord is a record of a processed event, added into the history of events,
// available via REST interface.
type EventRecord struct {
	SeqNum      uint64
	Name        string
	Description string
	Method      api.EventMethodType
	Handlers    []*EventHandlingRecord
	TxnError    error
}

// EventHandlingRecord is a record of an event being handled by a given handler.
type EventHandlingRecord struct {
	Handler string
	Revert  bool
	Error   error // nil if none
}

var (
	// ErrClosedController is returned when Controller is used when it is already closed.
	ErrClosedController = errors.New("controller was closed")
	// ErrEventQueueFull is returned when queue for events is full.
	ErrEventQueueFull = errors.New("queue with events is full")
)

// Init loads config file and starts the event loop.
func (c *Controller) Init() error {
	// initialize attributes
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.eventQueue = make(chan api.Event)
	c.startupResyncCheck = make(chan struct{})
	for i := len(c.EventHandlers) - 1; i >= 0; i-- {
		c.revEventHandlers = append(c.revEventHandlers, c.EventHandlers[i])
	}

	// default configuration
	c.config = &Config{
		DelayLocalResync:        defaultDelayLocalResync,
		StartupResyncDeadline:   defaultStartupResyncDeadline,
		RemoteDBProbingInterval: defaultRemoteDBProbingInterval,
	}

	// load configuration
	err := c.loadConfig(c.config)
	if err != nil {
		c.Log.Error(err)
	}
	c.Log.Infof("Controller configuration: %+v", *c.config)

	// start event loop
	c.wg.Add(1)
	go c.eventLoop()

	// start go routine that will send signal to check for status of startup
	// resync when timeout expires
	c.wg.Add(1)
	go c.signalStartupResyncCheck()
	return nil
}

// Init starts DB watcher and registers plugin with the status check.
func (c *Controller) AfterInit() error {
	// start DB watcher
	c.dbWatcher = newDBWatcher(&dbWatcherArgs{
		log:                     c.Log.NewLogger("dbwatcher"),
		agentPrefix:             c.ServiceLabel.GetAgentPrefix(),
		eventLoop:               c,
		localDB:                 c.LocalDB,
		remoteDB:                c.RemoteDB,
		resources:               c.DBResources,
		delayLocalResync:        c.config.DelayLocalResync,
		remoteDBProbingInterval: c.config.RemoteDBProbingInterval,
	})

	// status check
	if c.StatusCheck != nil {
		c.StatusCheck.Register(c.PluginName, nil)
	}
	return nil
}

// PushEvent adds the given event into the queue for processing.
func (c *Controller) PushEvent(event api.Event) error {
	select {
	case <-c.ctx.Done():
		return ErrClosedController
	case c.eventQueue <- event:
		return nil
	default:
		return ErrEventQueueFull
	}
}

// signalStartupResyncCheck sends signal after StartupResyncDeadline to check for
// status of the startup resync (it blocks other events).
func (c *Controller) signalStartupResyncCheck() {
	defer c.wg.Done()

	select {
	case <-c.ctx.Done():
		return
	case <-time.After(c.config.StartupResyncDeadline):
		c.startupResyncCheck <- struct{}{}
		return
	}
}

// eventLoop implements the main event loop for Contiv.
func (c *Controller) eventLoop() {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return

		case event := <-c.eventQueue:
			if c.resyncCount == 0 {
				// DBResync must be the first event to process
				_, isDBResync := event.(*api.DBResync)
				_, isKubeStateChange := event.(*api.KubeStateChange)
				_, isExtConfigChange := event.(*api.ExternalConfigChange)

				if !isDBResync {
					// ignore DB changes received before the first DBResync
					if !isKubeStateChange && !isExtConfigChange {
						// non-DB-change events will be replayed after the first resync
						c.delayedEvents = append(c.delayedEvents, event)
					}
					continue // wait until DBResync
				}
			}

			// process the received event + all the delayed events
			events := append([]api.Event{event}, c.delayedEvents...)
			for _, event := range events {
				err := c.processEvent(event)
				if err != nil {
					if _, fatalErr := err.(*api.FatalError); fatalErr {
						// fatal error -> let the Kubernetes to restart the agent
						c.StatusCheck.ReportStateChange(c.PluginName, statuscheck.Error, err)
						return
					}
				}
			}
			c.delayedEvents = []api.Event{}

		case <- c.startupResyncCheck:
			// check that startup resync was performed
			if c.resyncCount == 0 {
				err := fmt.Errorf("startup resync has not executed within the first %d seconds",
					c.config.StartupResyncDeadline/time.Second)
				c.StatusCheck.ReportStateChange(c.PluginName, statuscheck.Error, err)
				return
			}
		}
	}
}

// processEvent processes the next event.
func (c *Controller) processEvent(event api.Event) error {
	// 1. prepare for resync
	if event.Method() == api.Resync {
		c.resyncCount++
		if dbResync, isDBResync := event.(*api.DBResync); isDBResync {
			c.kubeStateData = dbResync.KubeState
		}
	}

	var (
		err           error
		isUpdate      bool
		withRevert    bool
		updateEvent   api.UpdateEvent
		eventHandlers []api.EventHandler
	)

	// 2. check if this is an update event
	if event.Method() == api.Update {
		updateEvent, isUpdate = event.(api.UpdateEvent)
		if !isUpdate {
			err = fmt.Errorf("invalid update event: %s", event.GetName())
			c.Log.Error(err)
			return err
		}
		withRevert = updateEvent.TransactionType() == api.RevertOnFailure
	}

	// 3. get the order in which the event handlers should be executed
	if isUpdate {
		if updateEvent.Direction() == api.Forward {
			eventHandlers = c.EventHandlers
		} else {
			// Reverse
			eventHandlers = c.revEventHandlers
		}
	} else {
		// resync
		eventHandlers = c.EventHandlers
	}

	// 4. filter out handlers which are actually not interested in the event
	eventHandlers = filterHandlersForEvent(event, eventHandlers)

	// 5. prepare record of the event for the history
	c.evSeqNum++
	evRecord := &EventRecord{
		SeqNum:      c.evSeqNum,
		Name:        event.GetName(),
		Description: event.String(),
		Method:      event.Method(),
	}

	// 6. print information about the new event
	c.printNewEvent(evRecord, eventHandlers)

	// 7. execute Update/Resync to build the transaction for vpp-agent
	txn := newTransaction(c.Scheduler)
	var (
		idx      int
		fatalErr bool
		abortErr bool
	)
	changes := make(map[string]string) // handler -> change description
	for idx = 0; idx < len(eventHandlers); idx++ {
		handler := eventHandlers[idx]

		// execute Update/Resync
		if isUpdate {
			var change string
			change, err = handler.Update(event, txn)
			if change != "" {
				changes[handler.String()] = change
			}
		} else {
			err = handler.Resync(event, txn, c.kubeStateData, c.resyncCount)
		}

		// record operation
		evRecord.Handlers = append(evRecord.Handlers, &EventHandlingRecord{
			Handler: handler.String(),
			Revert:  false,
			Error:   err,
		})

		// check if error allows to continue
		if err != nil {
			_, fatalErr = err.(*api.FatalError)
			_, abortErr = err.(*api.FatalError)
			if withRevert || fatalErr || abortErr {
				break
			}
		}
	}

	// 8. commit the transaction to the vpp-agent
	if err == nil || (!fatalErr && !abortErr && !withRevert) {
		description := event.GetName()
		if isUpdate {
			for handler, change := range changes {
				description += fmt.Sprintf("\n* %s: %s", handler, change)
			}
		}
		ctx := context.Background()
		ctx = scheduler.WithDescription(ctx, description)
		// TODO: make retry parameters configurable
		ctx = scheduler.WithRetry(ctx, time.Second, true)
		if withRevert {
			ctx = scheduler.WithRevert(ctx)
		}
		if !isUpdate {
			ctx = scheduler.WithFullResync(ctx)
		}
		err = txn.Commit(ctx)
		evRecord.TxnError = err
	}

	// 9. for events defined with revert, undo already executed operations
	if err != nil && withRevert && !fatalErr {
		// clear error - TODO: OK?
		err = nil

		// revert already executed changes
		for idx = idx-1; idx >= 0; idx-- {
			handler := eventHandlers[idx]
			err = handler.Revert(event)

			// record Revert operation
			evRecord.Handlers = append(evRecord.Handlers, &EventHandlingRecord{
				Handler: handler.String(),
				Revert:  true,
				Error:   err,
			})

			// check if error allows to continue
			if err != nil {
				if _, fatalErr = err.(*api.FatalError); fatalErr {
					break
				}
			}
		}
	}


	// 10. finalize event processing
	c.printFinalizedEvent(evRecord)
	c.eventHistory = append(c.eventHistory, evRecord)
	event.Done(err)

	// 11. if processing failed and the changes weren't (properly) reverted, suggest resync
	if err != nil && !fatalErr {
		// TODO: avoid frequent resyncs, if it is too much report error to status check
		c.dbWatcher.requestResync(false)
	}

	return err
}

// Close stops event loop and database watching.
func (c *Controller) Close() error {
	c.dbWatcher.close()
	c.cancel()
	c.wg.Wait()
	return nil
}

// loadConfig loads configuration file.
func (c *Controller) loadConfig(config *Config) error {
	found, err := c.Cfg.LoadValue(config)
	if err != nil {
		return err
	} else if !found {
		c.Log.Debugf("%v config not found", c.PluginName)
		return nil
	}
	c.Log.Debugf("%v config found: %+v", c.PluginName, config)

	return err
}

// printNewEvent prints a banner into stdout about a newly received event.
func (c *Controller) printNewEvent(eventRec *EventRecord, handlers []api.EventHandler) {
	border := strings.Repeat(">", 100)
	evDescLns := strings.Split(eventRec.Description, "\n")
	fmt.Println(border)
	fmt.Printf("*   NEW EVENT: %-70s %10s *\n", evDescLns[0], eventSeqNumToStr(eventRec.SeqNum))
	for i := 1; i < len(evDescLns); i++ {
		fmt.Printf("*              %-83s *\n", evDescLns[i])
	}
	fmt.Printf("*   EVENT HANDLERS: %-78s *\n", evHandlersToStr(handlers))
	fmt.Println(border)
}

// printNewEvent prints a banner into stdout about a finalized event.
func (c *Controller) printFinalizedEvent(eventRec *EventRecord) {
	var (
		handledBy  []string
		revertedBy []string
		hasErrors  bool
	)
	for _, handlerRec := range eventRec.Handlers {
		if handlerRec.Error != nil {
			hasErrors = true
		}
		if handlerRec.Revert {
			revertedBy = append(revertedBy, handlerRec.Handler)
		} else {
			handledBy = append(handledBy, handlerRec.Handler)
		}
	}

	border := strings.Repeat("<", 100)
	evDesc := strings.Split(eventRec.Description, "\n")[0]

	fmt.Println(border)
	fmt.Printf("*   FINALIZED EVENT: %-60s %10s *\n", evDesc, eventSeqNumToStr(eventRec.SeqNum))
	if len(handledBy) > 0 {
		fmt.Printf("*   HANDLED BY: %-78s *\n", strings.Join(handledBy, ", "))
	}
	if hasErrors {
		fmt.Printf("*   %-90s *\n", "ERRORS:")
		for _, handlerRec := range eventRec.Handlers {
			if handlerRec.Error == nil {
				continue
			}
			var withRevert string
			if handlerRec.Revert {
				withRevert = " (REVERT)"
			}
			errorDesc := fmt.Sprintf("%s%s: %s", handlerRec.Handler, withRevert, handlerRec.Error)
			fmt.Printf("*              %-80s *\n", errorDesc)
		}
	}
	if len(revertedBy) > 0 {
		fmt.Printf("*   REVERTED BY: %-78s *\n", strings.Join(revertedBy, ", "))
	}
	if eventRec.TxnError != nil {
		fmt.Printf("*   TRANSACTION ERROR: %-78v *\n", eventRec.TxnError)
	}
	fmt.Println(border)
}

// filterHandlersForEvent returns only those handlers that are actually interested in the event.
func filterHandlersForEvent(event api.Event, handlers []api.EventHandler) []api.EventHandler {
	var filteredHandlers []api.EventHandler
	for _, handler := range handlers {
		if handler.HandlesEvent(event) {
			filteredHandlers = append(filteredHandlers, handler)
		}
	}
	return filteredHandlers
}

// evHandlersToStr returns a string representing a list of event handlers.
func evHandlersToStr(handlers []api.EventHandler) string {
	var handlerStr []string
	for _, handler := range handlers {
		handlerStr = append(handlerStr, handler.String())
	}
	return strings.Join(handlerStr, ", ")
}

// eventSeqNumToStr returns string representing event sequence number.
func eventSeqNumToStr(seqNum uint64) string {
	return "#"+strconv.FormatUint(seqNum, 10)
}
