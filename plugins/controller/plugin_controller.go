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
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"sync"
	"time"

	"github.com/gogo/protobuf/proto"

	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/health/statuscheck"
	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/rpc/rest"
	"github.com/ligato/cn-infra/servicelabel"

	scheduler "github.com/ligato/vpp-agent/plugins/kvscheduler/api"

	"github.com/contiv/vpp/plugins/controller/api"
)

const (
	// how many events can be buffered at most
	eventQueueSize = 1000

	// by default, dbwatcher waits 5 seconds for connection to remoteDB
	// to be established before falling back to local DB resync
	// (but only if local DB is not empty)
	defaultDelayLocalResync = 5 * time.Second

	// by default, Controller will report error to status check if it does not
	// receive startup DBResync event within the first 30secs of runtime
	defaultStartupResyncDeadline = 30 * time.Second

	// by default, remote DB connection is probed every 3 seconds (with one GetValue)
	defaultRemoteDBProbingInterval = 3 * time.Second

	// by default, retry of failed configuration operations is enabled
	defaultEnableRetry = true

	// by default, retry is executed just 1sec after the failed operation
	defaultDelayRetry = time.Second

	// by default, retry delay grows exponentially with each failed attempt
	defaultEnableExpBackoffRetry = true

	// by default, periodic healing is disabled
	defaultEnablePeriodicHealing = false

	// by default, when enabled, periodic healing will run once every minute
	defaultPeriodicHealingInterval = time.Minute

	// by default, healing resync will start 5 seconds after a failed event processing
	defaultDelayAfterErrorHealing = 5 * time.Second
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

	dbWatcher      *dbWatcher
	kubeStateData  api.KubeStateData
	externalConfig api.ExternalConfig
	internalConfig api.KeyValuePairs

	evLoopGID          string // ID of the go routine running the event loop
	revEventHandlers   []api.EventHandler
	delayedEvents      []*QueuedEvent // events delayed until after the first resync
	eventQueue         chan *QueuedEvent
	followUpEventQueue chan *QueuedEvent // events sent from within the event loop
	startupResyncCheck chan struct{}

	healingScheduled bool
	resyncCount      int
	evSeqNum         uint64

	historyLock  sync.Mutex
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
	HTTPHandlers rest.HTTPHandlers

	EventHandlers []api.EventHandler

	LocalDB  keyval.KvProtoPlugin
	RemoteDB keyval.KvProtoPlugin
}

// Config holds the Controller configuration.
type Config struct {
	// retry
	EnableRetry           bool          `json:"enable-retry"`
	DelayRetry            time.Duration `json:"delay-retry"`
	EnableExpBackoffRetry bool          `json:"enable-exp-backoff-retry"`

	// startup resync
	DelayLocalResync      time.Duration `json:"delay-local-resync"`
	StartupResyncDeadline time.Duration `json:"startup-resync-deadline"`

	// healing
	EnablePeriodicHealing   bool          `json:"enable-periodic-healing"`
	PeriodicHealingInterval time.Duration `json:"periodic-healing-interval"`
	DelayAfterErrorHealing  time.Duration `json:"delay-after-error-healing"`

	// remote DB status
	RemoteDBProbingInterval time.Duration `json:"remotedb-probing-interval"`
}

// EventRecord is a record of a processed event, added into the history of events,
// available via REST interface.
type EventRecord struct {
	SeqNum      uint64
	IsFollowUp  bool
	FollowUpTo  uint64
	Name        string
	Description string
	Method      api.EventMethodType
	Handlers    []*EventHandlingRecord
	TxnError    error
}

// EventHandlingRecord is a record of an event being handled by a given handler.
type EventHandlingRecord struct {
	Handler  string
	Revert   bool
	Change   string // change description for update events
	Error    error  // nil if none
	ErrorStr string // string representation of the error (if any)
}

// QueuedEvent wraps event for the event queue.
type QueuedEvent struct {
	event           api.Event
	isFollowUp      bool
	followUpToEvent uint64 // event sequence number
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
	c.eventQueue = make(chan *QueuedEvent, eventQueueSize)
	c.followUpEventQueue = make(chan *QueuedEvent, eventQueueSize)
	c.startupResyncCheck = make(chan struct{}, 1)
	c.internalConfig = make(api.KeyValuePairs)
	for i := len(c.EventHandlers) - 1; i >= 0; i-- {
		c.revEventHandlers = append(c.revEventHandlers, c.EventHandlers[i])
	}

	// default configuration
	c.config = &Config{
		DelayLocalResync:        defaultDelayLocalResync,
		StartupResyncDeadline:   defaultStartupResyncDeadline,
		RemoteDBProbingInterval: defaultRemoteDBProbingInterval,
		EnableRetry:             defaultEnableRetry,
		DelayRetry:              defaultDelayRetry,
		EnableExpBackoffRetry:   defaultEnableExpBackoffRetry,
		EnablePeriodicHealing:   defaultEnablePeriodicHealing,
		PeriodicHealingInterval: defaultPeriodicHealingInterval,
		DelayAfterErrorHealing:  defaultDelayAfterErrorHealing,
	}

	// load configuration
	err := c.loadConfig(c.config)
	if err != nil {
		c.Log.Error(err)
	}
	c.Log.Infof("Controller configuration: %+v", *c.config)

	// register controller with status check
	if c.StatusCheck != nil {
		c.StatusCheck.Register(c.PluginName, nil)
	}

	// start event loop
	c.wg.Add(1)
	go c.eventLoop()

	// start go routine that will send signal to check for status of startup
	// resync when timeout expires
	c.wg.Add(1)
	go c.signalStartupResyncCheck()

	// register REST API handlers
	c.registerHandlers()
	return nil
}

// AfterInit starts DB watcher and registers plugin with the status check.
func (c *Controller) AfterInit() error {
	// start DB watcher
	c.dbWatcher = newDBWatcher(&dbWatcherArgs{
		log:                     c.Log.NewLogger("dbwatcher"),
		agentPrefix:             c.ServiceLabel.GetAgentPrefix(),
		eventLoop:               c,
		localDB:                 c.LocalDB,
		remoteDB:                c.RemoteDB,
		delayLocalResync:        c.config.DelayLocalResync,
		remoteDBProbingInterval: c.config.RemoteDBProbingInterval,
	})
	return nil
}

// PushEvent adds the given event into the queue for processing.
func (c *Controller) PushEvent(event api.Event) error {
	callerGID := getGID()
	if callerGID == c.evLoopGID {
		// follow up events (sent from within the event loop) should not be blocking
		// and will be prioritized (won't be overtaken by non-follow-up events)
		if event.IsBlocking() {
			panic("deadlock detected - blocking event sent from within the event loop")
		}
		select {
		case <-c.ctx.Done():
			return ErrClosedController
		case c.followUpEventQueue <- &QueuedEvent{
			event:           event,
			isFollowUp:      true,
			followUpToEvent: c.evSeqNum - 1}:
			return nil
		default:
			return ErrEventQueueFull
		}
	}

	select {
	case <-c.ctx.Done():
		return ErrClosedController
	case c.eventQueue <- &QueuedEvent{event: event}:
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

// periodicHealing triggers periodic resync from a separate go routine.
func (c *Controller) periodicHealing() {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-time.After(c.config.PeriodicHealingInterval):
			err := c.PushEvent(&api.HealingResync{Type: api.Periodic})
			if err != nil {
				c.Log.Warnf("Failed to trigger periodic healing resync: %v", err)
			}
		}
	}
}

// eventLoop implements the main event loop for Contiv.
func (c *Controller) eventLoop() {
	defer c.wg.Done()
	c.evLoopGID = getGID()

	for {
		select {
		case <-c.ctx.Done():
			return

		case event := <-c.followUpEventQueue:
			exit := c.receiveEvent(event)
			if exit {
				return
			}

		case event := <-c.eventQueue:
			exit := c.receiveEvent(event)
			if exit {
				return
			}

		case <-c.startupResyncCheck:
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

// receiveEvent receives event from the event queue.
func (c *Controller) receiveEvent(qe *QueuedEvent) (exitLoop bool) {
	// handle startup resync
	if c.resyncCount == 0 {
		// DBResync must be the first event to process
		if _, isDBResync := qe.event.(*api.DBResync); isDBResync {
			// once the startup resync is received,
			// periodic resync - if enabled - can be started
			if c.config.EnablePeriodicHealing {
				c.wg.Add(1)
				go c.periodicHealing()
			}
		} else {
			// events received before the first DBResync will be replayed afterwards
			c.delayedEvents = append(c.delayedEvents, qe)
			return false // wait until DBResync
		}
	}

	// process the received event + all the delayed events
	events := append([]*QueuedEvent{qe}, c.delayedEvents...)
	for len(events) > 0 {
		// check if there is any follow-up event
		if !qe.isFollowUp {
			select {
			case followUpEvent := <-c.followUpEventQueue:
				events = append([]*QueuedEvent{followUpEvent}, events...)
			default:
				// NOOP
			}
		}
		// pop and process the first event
		event := events[0]
		events = events[1:]
		err := c.processEvent(event)
		if err != nil {
			if _, fatalErr := err.(*api.FatalError); fatalErr {
				// fatal error -> let the Kubernetes to restart the agent
				c.StatusCheck.ReportStateChange(c.PluginName, statuscheck.Error, err)
				return true
			}
		}
	}
	c.delayedEvents = []*QueuedEvent{}
	return false
}

// processEvent processes the next event.
func (c *Controller) processEvent(qe *QueuedEvent) error {
	var (
		wasErr          error
		isUpdate        bool
		isHealing       bool
		healingAfterErr error
		periodicHealing bool
		withRevert      bool
		updateEvent     api.UpdateEvent
		eventHandlers   []api.EventHandler
	)
	event := qe.event

	// 1. prepare for resync
	if event.Method() == api.Resync {
		c.resyncCount++ // first resync has resyncCount == 1
		if dbResync, isDBResync := event.(*api.DBResync); isDBResync {
			c.kubeStateData = dbResync.KubeState
			c.externalConfig = dbResync.ExternalConfig
		}
		if healingResync, isHealingResync := event.(*api.HealingResync); isHealingResync {
			isHealing = true
			healingAfterErr = healingResync.Error
			periodicHealing = healingResync.Type == api.Periodic
			if !periodicHealing {
				c.healingScheduled = false
			}
		}
	}

	// 2. check if this is an update event
	if event.Method() == api.Update {
		updateEvent, isUpdate = event.(api.UpdateEvent)
		if !isUpdate {
			err := fmt.Errorf("invalid update event: %s", event.GetName())
			c.Log.Error(err)
			return err
		}
		withRevert = updateEvent.TransactionType() == api.RevertOnFailure

		// update Controller's view of DB
		if ksChange, isKSChange := event.(*api.KubeStateChange); isKSChange {
			c.kubeStateData[ksChange.Resource][ksChange.Key] = ksChange.NewValue
		}
		if extChangeEv, isExtChangeEv := event.(*api.ExternalConfigChange); isExtChangeEv {
			c.externalConfig[extChangeEv.Key] = extChangeEv.Value
		}
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
		if !isHealing || !periodicHealing {
			// periodic healing is just SB-sync, not handled in Contiv
			eventHandlers = c.EventHandlers
		}
	}

	// 4. filter out handlers which are actually not interested in the event
	eventHandlers = filterHandlersForEvent(event, eventHandlers)

	// 5. prepare record of the event for the history
	evRecord := &EventRecord{
		SeqNum:      c.evSeqNum,
		IsFollowUp:  qe.isFollowUp,
		FollowUpTo:  qe.followUpToEvent,
		Name:        event.GetName(),
		Description: event.String(),
		Method:      event.Method(),
	}
	c.evSeqNum++

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
		var err error
		handler := eventHandlers[idx]

		// execute Update/Resync
		var (
			change string
			errStr string
		)
		if isUpdate {
			change, err = handler.Update(event, txn)
			if change != "" {
				changes[handler.String()] = change
			}
		} else {
			err = handler.Resync(event, txn, c.kubeStateData, c.resyncCount)
		}
		if err != nil {
			errStr = err.Error()
			wasErr = err
		}

		// record operation
		evRecord.Handlers = append(evRecord.Handlers, &EventHandlingRecord{
			Handler:  handler.String(),
			Revert:   false,
			Change:   change,
			Error:    err,
			ErrorStr: errStr,
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

	// 8. merge internal (Contiv-generated) values with external configuration
	if !fatalErr && !abortErr {
		if isUpdate {
			var extChangeKey string
			if extChangeEv, isExtChangeEv := event.(*api.ExternalConfigChange); isExtChangeEv {
				// merge external config change with txn or with cached internal config
				extChangeKey = extChangeEv.Key
				txnVal, hasTxnVal := txn.values[extChangeKey]
				cachedVal, hasCachedVal := c.internalConfig[extChangeKey]
				if hasTxnVal {
					txn.merged[extChangeKey] = c.mergeLazyValIntoProto(extChangeKey, extChangeEv.Value, txnVal)
				} else if hasCachedVal {
					txn.merged[extChangeKey] = c.mergeLazyValIntoProto(extChangeKey, extChangeEv.Value, cachedVal)
				} else {
					txn.merged[extChangeKey] = extChangeEv.Value
				}
			}

			// merge internal config changes with the external config
			for key, value := range txn.values {
				if key == extChangeKey {
					// already merged
					continue
				}
				extVal, hasExtVal := c.externalConfig[key]
				if hasExtVal {
					txn.merged[key] = c.mergeLazyValIntoProto(key, extVal, value)
				}
			}
		} else if !periodicHealing {
			// (not downstream) resync
			for key, lazyVal := range c.externalConfig {
				txnVal, hasTxnVal := txn.values[key]
				if hasTxnVal {
					txn.merged[key] = c.mergeLazyValIntoProto(key, lazyVal, txnVal)
				} else {
					txn.merged[key] = lazyVal
				}
			}
		}
	}

	// 9. commit the transaction to the vpp-agent
	emptyTxn := len(txn.values) == 0 && len(txn.merged) == 0
	if (!emptyTxn || periodicHealing) &&
		(wasErr == nil || (!fatalErr && !abortErr && !withRevert)) {

		// prepare transaction context
		description := event.GetName()
		if isUpdate {
			for handler, change := range changes {
				description += fmt.Sprintf("\n* %s: %s", handler, change)
			}
		}
		ctx := context.Background()
		ctx = scheduler.WithDescription(ctx, description)
		if c.config.EnableRetry {
			ctx = scheduler.WithRetry(ctx, c.config.DelayRetry, c.config.EnableExpBackoffRetry)
		}
		if withRevert {
			ctx = scheduler.WithRevert(ctx)
		}
		if !isUpdate {
			if periodicHealing {
				ctx = scheduler.WithDownstreamResync(ctx)
			} else {
				ctx = scheduler.WithFullResync(ctx)
			}
		}

		// commit transaction to vpp-agent
		err := txn.Commit(ctx)
		evRecord.TxnError = err
		if err != nil {
			wasErr = err
		}

		// update Controller's view of internal configuration
		if isUpdate {
			if err == nil || !withRevert {
				for key, value := range txn.values {
					c.internalConfig[key] = value
				}
			}
		} else if !periodicHealing {
			c.internalConfig = txn.values
		}
	}

	// 10. for events defined with revert, undo already executed operations
	if wasErr != nil && withRevert && !fatalErr {
		// clear error - with reverting, only errors returned by Revert itself
		// should trigger the Healing resync
		wasErr = nil

		// revert already executed changes
		for idx = idx - 1; idx >= 0; idx-- {
			var errStr string
			handler := eventHandlers[idx]
			err := handler.Revert(event)
			if err != nil {
				errStr = err.Error()
				wasErr = err
			}

			// record Revert operation
			evRecord.Handlers = append(evRecord.Handlers, &EventHandlingRecord{
				Handler:  handler.String(),
				Revert:   true,
				Error:    err,
				ErrorStr: errStr,
			})

			// check if error allows to continue
			if err != nil {
				if _, fatalErr = err.(*api.FatalError); fatalErr {
					break
				}
			}
		}
	}

	// 11. finalize event processing
	c.printFinalizedEvent(evRecord)
	c.historyLock.Lock()
	c.eventHistory = append(c.eventHistory, evRecord)
	c.historyLock.Unlock()
	event.Done(wasErr)

	// 12. if Healing/AfterError resync has failed -> report error to status check
	if wasErr != nil && isHealing && !periodicHealing {
		err := fmt.Errorf("healing has not been successful (prev error: %v, healing error: %v)",
			healingAfterErr, wasErr)
		return api.NewFatalError(err)
	}

	// 13. if processing failed and the changes weren't (properly) reverted, trigger
	//     healing resync
	if wasErr != nil && !fatalErr && !c.healingScheduled {
		c.wg.Add(1)
		go c.scheduleHealing(wasErr)
		c.healingScheduled = true
	}

	return wasErr
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

// scheduleHealing is triggered to schedule Healing resync to run after a configurable
// time period.
func (c *Controller) scheduleHealing(afterErr error) {
	defer c.wg.Done()

	select {
	case <-c.ctx.Done():
		return

	case <-time.After(c.config.DelayAfterErrorHealing):
		err := c.PushEvent(&api.HealingResync{Type: api.AfterError, Error: afterErr})
		if err != nil {
			// fatal error -> let the Kubernetes to restart the agent
			err = fmt.Errorf("failed to trigger Healing resync: %v", err)
			c.StatusCheck.ReportStateChange(c.PluginName, statuscheck.Error, err)
		}
	}
}

// mergeLazyValIntoProto merges content of lazy value into a proto message.
func (c *Controller) mergeLazyValIntoProto(key string, value datasync.LazyValue, msg proto.Message) datasync.LazyValue {
	var err error
	defer func() {
		if err != nil {
			c.Log.Warnf("Failed to merge external with internal configuration for key: %s (%v)", key, err)
		}
	}()

	merge := proto.Clone(msg)
	output := &lazyValue{value: merge}

	valueType := proto.MessageType(proto.MessageName(merge))
	if valueType == nil {
		err = errors.New("invalid type")
		return output
	}
	protoVal := reflect.New(valueType.Elem()).Interface().(proto.Message)
	err = value.GetValue(protoVal)
	if err != nil {
		return output
	}
	proto.Merge(merge, protoVal)
	return output
}

// getGID returns the current go routine ID as string.
func getGID() string {
	goroutineLabel := []byte("goroutine ")
	b := make([]byte, 64)
	b = b[:runtime.Stack(b, false)]
	if !bytes.HasPrefix(b, goroutineLabel) {
		return "unknown"
	}
	b = bytes.TrimPrefix(b, goroutineLabel)
	b = b[:bytes.IndexByte(b, ' ')]
	return string(b)
}
