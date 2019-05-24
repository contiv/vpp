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
	"runtime"
	"sync"
	"time"

	"github.com/gogo/protobuf/proto"

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

	// how often the event history gets trimmed to remove records too old to keep
	eventHistoryTrimmingPeriod = 1 * time.Minute

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

	// by defauly, kvscheduler will attempt to retry failed operations at most
	// 3 times
	defaultMaxRetryAttempts = 3

	// by default, retry delay grows exponentially with each failed attempt
	defaultEnableExpBackoffRetry = true

	// by default, periodic healing is disabled
	defaultEnablePeriodicHealing = false

	// by default, when enabled, periodic healing will run once every minute
	defaultPeriodicHealingInterval = time.Minute

	// by default, healing resync will start 5 seconds after a failed event processing
	defaultDelayAfterErrorHealing = 5 * time.Second

	// by default, a history of processed events is recorded
	defaultRecordEventHistory = true

	// by default, only events processed in the last 24 hours are kept recorded
	// (with the exception of permanently recorded init period)
	defaultEventHistoryAgeLimit = 24 * 60 // in minutes

	// by default, events from the first hour of runtime are permanently recorded
	// in memory
	defaultPermanentlyRecordedInitPeriod = 60 // in minutes
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
	externalConfig map[string]api.KeyValuePairs // ext. source label -> config snapshot
	internalConfig api.KeyValuePairs

	evLoopGID            string // ID of the go routine running the event loop
	revEventHandlers     []api.EventHandler
	delayedEvents        []*QueuedEvent // events delayed until after the first resync
	eventQueue           chan *QueuedEvent
	followUpEventQueue   chan *QueuedEvent // events sent from within the event loop
	startupResyncCheck   chan struct{}
	eventHistoryTrimming chan struct{}

	healingScheduled bool
	resyncCount      int
	aborting         bool
	evSeqNum         uint64

	historyLock  sync.Mutex
	eventHistory []*EventRecord
	startTime    time.Time

	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc

	txn *kvSchedulerTxn // transaction associated to the event currently being processed
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

	ExtSources []ExternalConfigSource
}

// Config holds the Controller configuration.
type Config struct {
	// retry
	EnableRetry           bool          `json:"enableRetry"`
	DelayRetry            time.Duration `json:"delayRetry"`
	MaxRetryAttempts      int           `json:"maxRetryAttempts"`
	EnableExpBackoffRetry bool          `json:"enableExpBackoffRetry"`

	// startup resync
	DelayLocalResync      time.Duration `json:"delayLocalResync"`
	StartupResyncDeadline time.Duration `json:"startupResyncDeadline"`

	// healing
	EnablePeriodicHealing   bool          `json:"enablePeriodicHealing"`
	PeriodicHealingInterval time.Duration `json:"periodicHealingInterval"`
	DelayAfterErrorHealing  time.Duration `json:"delayAfterErrorHealing"`

	// remote DB status
	RemoteDBProbingInterval time.Duration `json:"remoteDBProbingInterval"`

	// event history
	RecordEventHistory            bool   `json:"recordEventHistory"`
	EventHistoryAgeLimit          uint32 `json:"eventHistoryAgeLimit"`
	PermanentlyRecordedInitPeriod uint32 `json:"permanentlyRecordedInitPeriod"`
}

// EventRecord is a record of a processed event, added into the history of events,
// available via REST interface.
type EventRecord struct {
	SeqNum          uint64
	ProcessingStart time.Time
	ProcessingEnd   time.Time
	IsFollowUp      bool
	FollowUpTo      uint64
	Name            string
	Description     string
	Method          api.EventMethodType
	Handlers        []*EventHandlingRecord
	TxnError        error
	Txn             *scheduler.RecordedTxn
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

// ExternalConfigSource defines API that a source of external configuration
// must implement.
type ExternalConfigSource interface {
	// String identifies the external config source for the Controller.
	// Note: Plugins already implement Stringer.
	String() string

	// GetConfigSnapshot should return full configuration snapshot that is
	// required by the external source to be applied at the given moment.
	GetConfigSnapshot() (api.KeyValuePairs, error)
}

var (
	// ErrClosedController is returned when Controller is used when it is already closed.
	ErrClosedController = errors.New("controller was closed")
	// ErrEventQueueFull is returned when queue for events is full.
	ErrEventQueueFull = errors.New("queue with events is full")
	// ErrEventLoopIsAborting returned to an event producer via method Event.Done()
	// when event loop is aborting after a fatal error has occurred.
	ErrEventLoopIsAborting = errors.New("event loop is aborting after a fatal error")
)

// Init loads config file and starts the event loop.
func (c *Controller) Init() error {
	// initialize attributes
	c.startTime = time.Now()
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.eventQueue = make(chan *QueuedEvent, eventQueueSize)
	c.followUpEventQueue = make(chan *QueuedEvent, eventQueueSize)
	c.startupResyncCheck = make(chan struct{}, 1)
	c.eventHistoryTrimming = make(chan struct{}, 1)
	c.internalConfig = make(api.KeyValuePairs)
	c.externalConfig = make(map[string]api.KeyValuePairs)
	for i := len(c.EventHandlers) - 1; i >= 0; i-- {
		c.revEventHandlers = append(c.revEventHandlers, c.EventHandlers[i])
	}

	// default configuration
	c.config = &Config{
		DelayLocalResync:              defaultDelayLocalResync,
		StartupResyncDeadline:         defaultStartupResyncDeadline,
		RemoteDBProbingInterval:       defaultRemoteDBProbingInterval,
		EnableRetry:                   defaultEnableRetry,
		DelayRetry:                    defaultDelayRetry,
		MaxRetryAttempts:              defaultMaxRetryAttempts,
		EnableExpBackoffRetry:         defaultEnableExpBackoffRetry,
		EnablePeriodicHealing:         defaultEnablePeriodicHealing,
		PeriodicHealingInterval:       defaultPeriodicHealingInterval,
		DelayAfterErrorHealing:        defaultDelayAfterErrorHealing,
		RecordEventHistory:            defaultRecordEventHistory,
		EventHistoryAgeLimit:          defaultEventHistoryAgeLimit,
		PermanentlyRecordedInitPeriod: defaultPermanentlyRecordedInitPeriod,
	}

	// load configuration
	err := c.loadConfig(c.config)
	if err != nil {
		c.Log.Error(err)
		return err
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

	// start go routine that will be sending signals to remove event records
	// too old to keep
	if c.config.RecordEventHistory {
		c.wg.Add(1)
		go c.signalEventHistoryTrimming()
	}

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

// GetConfig returns value for the given key in the controller's transaction. If data for
// the key is not part of the transaction stored value from internal config is returned.
func (c *Controller) GetConfig(key string) proto.Message {
	val, found := c.txn.values[key]
	if !found {
		val = c.internalConfig[key]
	}
	if val == nil {
		return nil
	}
	return proto.Clone(val)
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

// signalEventHistoryTrimming periodically sends signal to remove event records
// too old to keep.
func (c *Controller) signalEventHistoryTrimming() {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-time.After(eventHistoryTrimmingPeriod):
			c.eventHistoryTrimming <- struct{}{}
		}
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

	c.Log.Info("Starting the main event loop")
	defer func() {
		c.Log.Info("Stopping the main event loop")
	}()

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
				c.aborting = true
				for _, de := range c.delayedEvents {
					de.event.Done(ErrEventLoopIsAborting)
				}
			}

		case <-c.eventHistoryTrimming:
			c.historyLock.Lock()
			now := time.Now()
			ageLimit := time.Duration(c.config.EventHistoryAgeLimit) * time.Minute
			initPeriod := time.Duration(c.config.PermanentlyRecordedInitPeriod) * time.Minute
			var i, j int // i = first after init period, j = first after init period to keep
			for i = 0; i < len(c.eventHistory); i++ {
				sinceStart := c.eventHistory[i].ProcessingStart.Sub(c.startTime)
				if sinceStart > initPeriod {
					break
				}
			}
			for j = i; j < len(c.eventHistory); j++ {
				elapsed := now.Sub(c.eventHistory[j].ProcessingEnd)
				if elapsed <= ageLimit {
					break
				}
			}
			if j > i {
				copy(c.eventHistory[i:], c.eventHistory[j:])
				newLen := len(c.eventHistory) - (j - i)
				for k := newLen; k < len(c.eventHistory); k++ {
					c.eventHistory[k] = nil
				}
				c.eventHistory = c.eventHistory[:newLen]
			}
			c.historyLock.Unlock()
		}
	}
}

// receiveEvent receives event from the event queue.
func (c *Controller) receiveEvent(qe *QueuedEvent) (exitLoop bool) {
	// handle startup resync
	if c.resyncCount == 0 && !c.aborting {
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
		var err error
		ev := events[0]
		events = events[1:]
		if !c.aborting {
			err = c.processEvent(ev)
		} else {
			err = ErrEventLoopIsAborting
			ev.event.Done(err)
		}
		if err != nil {
			if _, fatalErr := err.(*api.FatalError); fatalErr {
				// fatal error -> let the Kubernetes to restart the agent
				c.StatusCheck.ReportStateChange(c.PluginName, statuscheck.Error, err)
				c.aborting = true
			}
		}
		if _, isShutdown := ev.event.(*api.Shutdown); isShutdown {
			// agent is shutting down
			return true
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
		needsHealing    bool
		healingAfterErr error
		withRevert      bool
		withHealing     bool
		updateEvent     api.UpdateEvent
		eventHandlers   []api.EventHandler
	)
	event := qe.event

	// 1. prepare for resync
	if event.Method() != api.Update {
		c.resyncCount++ // first resync has resyncCount == 1
		if dbResync, isDBResync := event.(*api.DBResync); isDBResync {
			c.kubeStateData = dbResync.KubeState
			c.externalConfig[dbExtCfgSrc] = dbResync.ExternalConfig
			// reload other external config sources as well
			for _, extSource := range c.ExtSources {
				sourceName := extSource.String()
				config, err := extSource.GetConfigSnapshot()
				if err != nil {
					c.Log.Errorf("Failed to re-load external config from source %s: %v",
						sourceName, err)
					continue
				}
				c.externalConfig[sourceName] = config
			}
		}
		if extResyncEv, isExtResyncEv := event.(*api.ExternalConfigResync); isExtResyncEv {
			c.externalConfig[extResyncEv.Source] = extResyncEv.ExternalConfig
		}
		if healingResync, isHealingResync := event.(*api.HealingResync); isHealingResync {
			isHealing = true
			healingAfterErr = healingResync.Error
			if healingResync.Type != api.Periodic {
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
		withHealing = updateEvent.TransactionType() != api.BestEffortIgnoreErrors

		// update Controller's view of DB
		if ksChange, isKSChange := event.(*api.KubeStateChange); isKSChange {
			if ksChange.NewValue == nil {
				delete(c.kubeStateData[ksChange.Resource], ksChange.Key)
			} else {
				c.kubeStateData[ksChange.Resource][ksChange.Key] = ksChange.NewValue
			}
		}
		if extChangeEv, isExtChangeEv := event.(*api.ExternalConfigChange); isExtChangeEv {
			source := extChangeEv.Source
			for key, value := range extChangeEv.UpdatedKVs {
				if value == nil {
					delete(c.externalConfig[source], key)
				} else {
					c.externalConfig[source][key] = value
				}
			}
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
		if event.Method() != api.DownstreamResync {
			eventHandlers = c.EventHandlers
		}
	}

	// 4. filter out handlers which are actually not interested in the event
	eventHandlers = filterHandlersForEvent(event, eventHandlers)

	// 5. prepare record of the event for the history
	evRecord := &EventRecord{
		SeqNum:          c.evSeqNum,
		ProcessingStart: time.Now(),
		IsFollowUp:      qe.isFollowUp,
		FollowUpTo:      qe.followUpToEvent,
		Name:            event.GetName(),
		Description:     event.String(),
		Method:          event.Method(),
	}
	c.evSeqNum++

	// 6. print information about the new event
	c.printNewEvent(evRecord, eventHandlers)

	// 7. execute Update/Resync to build the transaction for vpp-agent
	c.txn = newTransaction(c.Scheduler)
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
			change, err = handler.Update(event, c.txn)
			if change != "" {
				changes[handler.String()] = change
			}
		} else {
			err = handler.Resync(event, c.kubeStateData, c.resyncCount, c.txn)
		}
		if err != nil {
			errStr = err.Error()
			wasErr = err
			if !withRevert && withHealing {
				needsHealing = true
			}
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
			merged := make(map[string]struct{}) // a set of keys with already merged values
			if extChangeEv, isExtChangeEv := event.(*api.ExternalConfigChange); isExtChangeEv {
				for key, extVal := range extChangeEv.UpdatedKVs {
					// merge external config change with txn or with cached internal config
					txnVal, hasTxnVal := c.txn.values[key]
					cachedVal, hasCachedVal := c.internalConfig[key]
					if hasTxnVal {
						c.txn.merged[key] = c.mergeValues(txnVal, extVal)
					} else if hasCachedVal {
						c.txn.merged[key] = c.mergeValues(cachedVal, extVal)
					} else {
						c.txn.merged[key] = extVal
					}
					merged[key] = struct{}{}
				}
			}

			// merge internal config changes with the external config
			for key, txnVal := range c.txn.values {
				if _, alreadyMerged := merged[key]; alreadyMerged {
					// already merged
					continue
				}
				// merge with value from the first source with a match
				for source := range c.externalConfig {
					extVal, hasExtVal := c.externalConfig[source][key]
					if hasExtVal {
						c.txn.merged[key] = c.mergeValues(txnVal, extVal)
						break
					}
				}
			}
		} else if event.Method() != api.DownstreamResync {
			for source := range c.externalConfig {
				for key, extVal := range c.externalConfig[source] {
					txnVal, hasTxnVal := c.txn.values[key]
					if hasTxnVal {
						c.txn.merged[key] = c.mergeValues(txnVal, extVal)
					} else {
						c.txn.merged[key] = extVal
					}
				}
			}
		}
	}

	// 9. commit the transaction to the vpp-agent
	emptyTxn := len(c.txn.values) == 0 && len(c.txn.merged) == 0
	if (!emptyTxn || !isUpdate) &&
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
			ctx = scheduler.WithRetry(ctx, c.config.DelayRetry, c.config.MaxRetryAttempts, c.config.EnableExpBackoffRetry)
		}
		if withRevert {
			ctx = scheduler.WithRevert(ctx)
		}
		if !isUpdate {
			switch event.Method() {
			case api.UpstreamResync:
				ctx = scheduler.WithResync(ctx, scheduler.UpstreamResync, false)
			case api.DownstreamResync:
				ctx = scheduler.WithResync(ctx, scheduler.DownstreamResync, false)
			case api.FullResync:
				ctx = scheduler.WithResync(ctx, scheduler.FullResync, c.resyncCount == 1)
			}
		}

		// commit transaction to vpp-agent
		txnSeqNum, err := c.txn.Commit(ctx)
		c.Log.Debugf("Transaction commit result: err=%v", err)

		// handle transaction error
		evRecord.TxnError = err
		if err != nil {
			wasErr = err
			if !withRevert && withHealing {
				if c.onlyExtConfigFailed(err.(*scheduler.TransactionError), c.txn.values) {
					c.Log.Debug("Only external configuration caused the transaction to fail - " +
						"not scheduling Healing resync")
				} else {
					needsHealing = true
				}
			}
		}

		// append transaction to the event record
		if txnSeqNum != ^uint64(0) {
			evRecord.Txn = c.Scheduler.GetRecordedTransaction(txnSeqNum)
		}

		// update Controller's view of internal configuration
		if isUpdate {
			if err == nil || !withRevert {
				for key, value := range c.txn.values {
					if value == nil {
						delete(c.internalConfig, key)
					} else {
						c.internalConfig[key] = value
					}
				}
			}
		} else if event.Method() != api.DownstreamResync {
			c.internalConfig = c.txn.values
		}
	}

	// 10. for events defined with revert, undo already executed operations
	if wasErr != nil && withRevert && !fatalErr {
		// revert already executed changes
		for idx = idx - 1; idx >= 0; idx-- {
			var errStr string
			handler := eventHandlers[idx]
			err := handler.Revert(event)
			if err != nil {
				errStr = err.Error()
				wasErr = err
				needsHealing = true
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
	evRecord.ProcessingEnd = time.Now()
	c.printFinalizedEvent(evRecord)
	if c.config.RecordEventHistory {
		c.historyLock.Lock()
		c.eventHistory = append(c.eventHistory, evRecord)
		c.historyLock.Unlock()
	}
	event.Done(wasErr)
	c.txn = nil

	// 12. if Healing/AfterError resync has failed -> report error to status check
	if needsHealing && isHealing && healingAfterErr != nil {
		err := fmt.Errorf("healing has not been successful (prev error: %v, healing error: %v)",
			healingAfterErr, wasErr)
		return api.NewFatalError(err)
	}

	// 13. if processing failed and the changes weren't (properly) reverted, trigger
	//     healing resync
	if needsHealing && !fatalErr && !c.healingScheduled {
		c.wg.Add(1)
		go c.scheduleHealing(wasErr)
		c.healingScheduled = true
	}

	return wasErr
}

// onlyExtConfigFailed returns true if external input caused the transaction
// to fail and not the internal configuration.
func (c *Controller) onlyExtConfigFailed(txnErr *scheduler.TransactionError, txnInternalValues api.KeyValuePairs) bool {
	if txnErr.GetTxnInitError() != nil {
		return false
	}
	for _, kv := range txnErr.GetKVErrors() {
		if _, inTxnInternalVals := txnInternalValues[kv.Key]; inTxnInternalVals {
			return false
		}
		if _, inInternalCfg := c.internalConfig[kv.Key]; inInternalCfg {
			return false
		}
	}
	return true
}

// getEventHistory returns history of events run within the specified
// time window, or the full recorded history if the timestamps are zero values.
// The method assumes that historyLock is being held.
func (c *Controller) getEventHistory(since, until time.Time) (history []*EventRecord) {
	if !since.IsZero() && !until.IsZero() && until.Before(since) {
		// invalid time window
		return
	}

	lastBefore := -1
	firstAfter := len(c.eventHistory)

	if !since.IsZero() {
		for ; lastBefore+1 < len(c.eventHistory); lastBefore++ {
			if !c.eventHistory[lastBefore+1].ProcessingEnd.Before(since) {
				break
			}
		}
	}

	if !until.IsZero() {
		for ; firstAfter > 0; firstAfter-- {
			if !c.eventHistory[firstAfter-1].ProcessingStart.After(until) {
				break
			}
		}
	}

	return c.eventHistory[lastBefore+1 : firstAfter]
}

// Close stops event loop and database watching.
func (c *Controller) Close() error {
	// send shutdown event first
	shutdownEv := api.NewShutdownEvent()
	c.PushEvent(shutdownEv)
	err := shutdownEv.Wait()

	// close all go routines
	c.dbWatcher.close()
	c.cancel()
	c.wg.Wait()
	return err
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

// mergeValues merges two proto messages into one.
func (c *Controller) mergeValues(dst, src proto.Message) proto.Message {
	if dst == nil {
		return src
	}
	if src == nil {
		return dst
	}

	merge := proto.Clone(dst)
	proto.Merge(merge, src)
	return merge
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
