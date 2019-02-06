# Main event loop of Contiv/VPP

Contiv/VPP is based on a **single-threaded event loop model** to handle concurrent
inputs from multiple data sources. This model significantly simplifies debugging
and limits potential race conditions. The amount of data that flows through the
Contiv isn't large enough a contains too many inter-dependencies for a parallel
processing to bring any measurable improvements.

## Basic concepts

The event loop can be viewed as a single FIFO message queue with an unlimited
number of producers on one end, and a chain of consumers processing the
messages in sequence on the receiving side. In this case, producers are sources
of external or even internal input data, messages are events packaged with all
the input arguments, and consumers, better known as event handlers, are typically
Contiv plugins reacting to events synchronously. Anything from change in the
Kubernetes state data, notification from VPP or even asynchronous signal sent
from within a Contiv plugin, can and should be represented as an event, dispatched
through the loop into the target event handler for processing. Even though it
cannot be enforced, it is strongly recommended to avoid reacting to asynchronous
input signals from outside of this main event loop. Separate go routines are still
allowed to watch for input signals, but their processing should be delegated
through the loop into the handlers even if they reside inside the same plugin
to maintain the single-threaded model.

The event handlers register themselves against the event loop (in the compile-time).
The order of registrations is important - received events are being dispatched
to the handlers exactly in this order. If plugin `B` needs to read the state of
plugin `A` through its API, i.e. plugin `B` depends on `A`, and both plugins are
handlers for at least one common event, then plugin `A` should be registered
before `B` to ensure, that when plugin `B` receives an event, it can access
plugin `A` knowing that it has already updated its state to reflect the event.
First few plugins in the chain of event handlers are therefore core plugins
providing some basic functionally, used by more specialized plugins that follow.

The outcome of event processing can be threefold:
* update of the internal state of event handlers
* update/resync of the VPP/Linux configuration for the [ligato/VPP-Agent][ligato-vpp-agent] to apply
* dispatching of a new **follow-up** event

What to remember internally is fully in the reign of individual event handlers.
For example, there is already a [plugin][podmanager] that remembers and exposes
the set of locally configured pods with some docker-specific details,
or a [plugin][nodesync] which maintains a map of all nodes in the cluster with
their IPs and IDs. New plugin can use the APIs of these and other core
plugins to access already cached information, and internally maintain only
state data specific to its purpose.

Update and Resync configuration data for the [ligato/VPP-Agent][ligato-vpp-agent]
to apply are collected for every event into a single transaction. Event handlers
can add or even edit already added configuration items into the transaction.
Once all event handlers processed an event, the transaction, if non-empty, will
be committed to the VPP-agent. Therefore, even if Contiv is split into multiple
plugins, configuration changes corresponding to a single event are always applied
together as one transaction.

Sometimes, the outcome of an event processing is just yet another event to be
processed, sent from within the go routine running the main event loop, that
follows from the current event and therefore is denoted as **follow-up**.
Such events takes priority and overtake all the already enqueued events,
to avoid interleaving between follow-ups and unrelated events.

![Event loop diagram][event-loop-diagram]

## Event loop interface

The event loop is implemented by the [Controller plugin][controller-plugin].
The API of the event loop and of all of the related objects can be found in the
[api][controller-api] sub-package.

### Event
The [API][controller-el-api] of the Controller plugin defines Event as an object
implementing the `Event` interface:

```
// Event represents something that has happened and may cause some reaction.
type Event interface {
	// GetName should return a string identifier, unique among the event types,
	// but also somewhat descriptive for humans.
	GetName() string

	// String should return a description of the event.
	String() string

	// Method tells whether the event can be reacted to by an incremental change
	// (Update) or if a full re-synchronization is needed (Resync, i.e. complex
	// change).
	Method() EventMethodType

	// IsBlocking should return true if any producer of this event ever waits
	// for the event result (sent using the method Done()).
	IsBlocking() bool

	// Done is used to mark the event as processed.
	// A specific Event implementation may use this method for example to deliver
	// the return value back to the send of the event.
	Done(error)
}
```

`GetName()` should return a relatively short label for the event, whereas
`String()` can provide more detailed description.

`Method()` is used to recognize two classes of events:
* **Update events**: reacted to by an incremental change in the configuration
  for the VPP-Agent to apply (for example "Add pod", "Delete pod", "Connect other
  node", etc);
* **Resync events**: used for complex changes which require full re-calculation
  of the currently desired Linux/VPP configuration, and potentially also full
  refresh of the internal state data of event handlers, depending on what
  specific kind of resync it is (for example: "DB resync", "DHCP-assigned
  Node IP change", etc.).
  Based on the scope of data to resynchronize, the resync is further divided
  into the modes:
    - `Full Resync`: desired configuration is re-calculated by Contiv plugins,
      the view of SB plane (VPP/Linux) is refreshed and inconsistencies are
      resolved using CRUD operations by the VPP-Agent.
    - `Upstream resync`: partial resync; same as Full resync except the view
      of SB plane is assumed to be up-to-date and will not get refreshed.
      It is used by Contiv when it is easier to re-calculate the desired state
      rather than to determine the (minimal) difference.
    - `Downstream resync`: partial resync; unlike Full resync the Contiv plugins
      are not asked to Resync their state, i.e. `Resync` methods of event handlers
      are not called - the event is fully handled by the Controller, instead
      the last state of Contiv-requested configuration is assumed to be up-to-date
      and re-used by VPP-Agent to perform resync with the data plane.
      In Contiv, the Downstream resync is used for periodical Healing resync,
      which, if enabled, can execute without any interaction with event handlers.

If event producer(s) need to wait for the result of the transaction associated
with the event, `IsBlocking()` should return `true` and `Done(error)` can be
used to propagate the error back to the producer (e.g. via channel).
For an example of a blocking event, see [AddPod][podmanager-api] event defined
by [podmanager][podmanager] plugin.

Update (non-resync) events, also have to implement the `UpdateEvent` interface:
```
// UpdateEvent can be reacted to by an incremental change, as opposed to the full
// re-synchronization.
type UpdateEvent interface {
	// TransactionType defines how to treat already executed changes of a failed
	// event processing - whether to keep them (and be as close to the desired
	// state as it was possible) or to revert them (a proper transaction).
	TransactionType() UpdateTransactionType

	// Direction determines the direction in which the event should flow through
	// the event handlers.
	Direction() UpdateDirectionType
}
```
With `TransactionType()` it is possible to define how to treat transaction
errors - either to rollback failed transaction (`RevertOnFailure`) or to keep
effects of successful operations to be as close to the desired state as it is
possible. For example, if we fail to connect pod with VPP, we revert all the
changes and return error back to Kubernetes, which sends new request for a
re-created container soon after. Resync events, on the other hand, are all
handled in the best-effort mode (revert makes no sense).

`Direction()` allows to change the direction in which the event should flow
through the chain of event handlers. By default, the events are processed
in the order or registrations, but for events *un-doing* changes, the reverse
direction may be preferred (for example [DeletePod][podmanager-api]).

### Event Loop
Controller plugin exposes simple interface for event dispatching:
```
type EventLoop interface {
	// PushEvent adds the given event into the queue for processing.
	PushEvent(event Event) error
}
```
`PushEvent` adds the event at the back of the event queue. The error returned
by the method covers only the enqueue procedure itself, not the event
processing, which from the event producer point of view executes asynchronously.
For blocking events, the producer may wait for the event handling result after
the event has been pushed. Here is an excerpt from the [podmanager][podmanager]
plugin showing how to push and then wait for the event:
```
	// push AddPod event and wait for the result
	event := NewAddPodEvent(request)
	err = pm.EventLoop.PushEvent(event)
	if err == nil {
		err = event.Wait()
	}
```

### Event Handler

Event handler is typically a plugin which handles one or more events.
For a plugin to become an event handler, ready to be registered with the event
loop, it first must implement the `EventHandler` interface:
```
// EventHandler declares methods that event handler must implement.
type EventHandler interface {
	// String identifies the handler for the Controller and in the logs.
	// Note: Plugins already implement Stringer.
	String() string

	// HandlesEvent is used by Controller to check if the event is being handled
	// by this handler.
	HandlesEvent(event Event) bool

	// Resync is called by Controller to handle event that requires full
	// re-synchronization.
	// For startup resync, resyncCount is 1. Higher counter values identify
	// run-time resync.
	Resync(event Event, kubeStateData KubeStateData, resyncCount int, txn ResyncOperations) error

	// Update is called by Controller to handle event that can be reacted to by
	// an incremental change.
	// <changeDescription> should be human-readable description of changes that
	// have to be performed (via txn or internally) - can be empty.
	Update(event Event, txn UpdateOperations) (changeDescription string, err error)

	// Revert is called to revert already executed internal changes (in the plugin
	// itself, not in VPP/Linux network stack) for a RevertOnFailure event that
	// has failed in the processing.
	Revert(event Event) error
}
```

`HandlesEvent(event)` is a predicate that allows to filter incoming events and
select only those that the plugin is actually interested in. Plugins that build
at least some configuration for VPP-agent should select any resync event,
otherwise their configuration would get removed during the resynchronization.
Event can be filtered not only by its name, but also based on the content,
for example:
```
// HandlesEvent selects any resync event and KubeStateChange for specific resources to handle.
func (p *Plugin) HandlesEvent(event controller.Event) bool {
	if event.Method() != controller.Update {
		// select any resync event
		return true
	}
	if ksChange, isKSChange := event.(*controller.KubeStateChange); isKSChange {
		switch ksChange.Resource {
		case namespace.NamespaceKeyword:
			return true
		case pod.PodKeyword:
			return true
		case policy.PolicyKeyword:
			return true
		default:
			// unhandled Kubernetes state change
			return false
		}
	}

	// unhandled event
	return false
}
```

When a given event is selected by `HandlesEvent`, it is then passed for processing
through `Update()` or `Resync()`, depending on the event method (as given by
`Event.Method()`). Together with the event, a handler is also given reference
to the associated [transaction][controller-txn-api], created to collect VPP/Linux
configuration changes to be installed to reflect the event.

The handler may return error from `Update`/`Resync` wrapped in either:
* [FatalError][controller-error-api] to signal that the agent should be
  terminated (and restarted by k8s), or
* [AbortEventError][controller-error-api] to signal that the processing of the
  event should not continue and a resync is needed.

Non-fatal, non-abort error signals the controller that something is wrong and
a resync is needed, but if the transaction is of type `BestEffort`, then
the current event processing will continue.

For update events which are defined to be reverted on failure, the Controller
will call `Revert` method on all the handlers that already processed the event,
but in the reverse order so that they can undo internal state changes.

Event handlers are registered for event processing by listing them in the slice
`EventHandlers` from the dependencies of the Controller plugin. Remember that
if plugin `B` depends on `A`, then `A` must be listed before `B`.
For example, here is an excerpt from `main.go` of the Contiv agent, where all
the dependency injection takes place:
```
	controller := controller.NewPlugin(controller.UseDeps(func(deps *controller.Deps) {
		//...
		deps.EventHandlers = []controller_api.EventHandler{
			contivConf,
			nodeSyncPlugin,
			podManager,
			ipamPlugin,
			ipv4NetPlugin,
			servicePlugin,
			policyPlugin,
			statsCollector,
		}
		//...
	}))
```

## Event loop implementation

The main event loop is implemented by the [Controller plugin][controller-plugin],
inside the plugin's [main implementation file][controller-impl].

Here is a summary of key methods and their purpose:
* `Controller.PushEvent`: adds new event into the queue for processing; the method
  basically implements the `EventLoop` interface and it is used by all event
  producers to request processing of new events;
* `Controller.eventLoop()`: runs infinite cycle, waiting for new events to be
  processed or for signals requesting to perform various actions, such us to
  cleanup the history of events or to terminate the agent;
* `Controller.receiveEvent()`: is called to grab new event when it arrives; the
  method must ensure that events received before the **startup** resync are
  delayed until the resync has executed and also that follow-up events are
  processed with a priority over normal events;
* `Controller.processEvent()`: processed received event, see [below](#event-processing)
  for a detailed description;
* `Controller.signalStartupResyncCheck()`: first resync, better known as **startup
  resync**, must execute before any other events - the event loop cannot delay
  event processing for too long, however, therefore the [Controller configuration][controller-config]
  allows to specify the deadline for startup resync (time limit measured since
  the start of the agent). `signalStartupResyncCheck` sends signal to `eventLoop`
  once this timeout elapses to check if the agent is already in-sync. If the check
  is negative, the agent process will be restarted using the [statuscheck plugin][statuscheck];
* `Controller.signalEventHistoryTrimming`: the controller maintains a history
  of processed events exposed via [REST interface][controller-rest]. The history
  cannot grow infinitely, however, instead it must be periodically trimmed off
  too old records (maximum age of records can be configured, by default it is
  24 hours). `signalEventHistoryTrimming` keeps sending periodic signals to
  remove event records exceeding the age limit;
* `Controller.periodicHealing`: the controller allows to enable periodic
  re-synchronization between intended and the actual VPP/Linux configuration.
  By default this is disabled, but when turned on, `periodicHealing` will keep
  sending signals in the configured time period to run the so-called **periodic
  Healing resync**;
* `Controller.scheduleHealing`: when event processing fails - the error being
  thrown by one of the handlers or the VPP-Agent - the controller will schedule
  a so-called **after-error Healing resync** using this method, hoping that
  re-synchronization of all event handlers and of the network configuration might
  resolve the issue. But when Healing resync fails as well, the agent is set
  for hard-restart using the [statuscheck plugin][statuscheck];

### Event processing

Processing of a single event is handled by the `Controller.processEvent()` method.
The processing is split into 13 steps:
1. For resync events that carry [external configuration][external-config-guide]
   or [Kubernetes state data][db-resources] snapshots (`DBResync` and
   `ExternalConfigResync`, defined [here][controller-db-api]) - basically the
   input data for Contiv - the controller must refresh the local [caches][controller-caches].
2. Updates (incremental changes) of input data must also be reflected in the
   local caches.
3. The order in which the event handlers should be called is determined.
4. Handlers which are not interested in the event (`HandlesEvent(event)` returns
   `false`) are excluded from the list of handlers for the event.
5. A record of event processing is prepared, but it is not added into the history
   until the outcome is known.
6. Information about a newly received event is printed to `stdout` - [scroll down](#event-logging)
   for more information about event logging.
7. `Update`/`Resync` methods of all selected event handlers are called in sequence
    and in the right order.
8. [External configuration][external-config-guide] may overlap with the
   configuration generated internally in Contiv plugins - the Controller
   must call `proto.Merge` on all overlapping values before submitting the
   changes to the VPP-Agent.
9. The transaction with changes collected from all event handlers is committed
   to the VPP-Agent.
10. If any of the previous steps has failed and this is an update event with
    reverting enabled, then in this step the Controller calls `Revert` method
    on all handlers that have already processed the event, but in the reverse
    order to allow them to undo plugin-internal state changes.
11. Information about processed event is [logged](#event-logging) and a record
    is added into the history. Event method `Done(error)` is called to potentially
    propagate error back to the producer (of a blocking event).
12. If this was an [after-error Healing resync][controller-healing-api] and the
    processing has failed, the Controller signals fatal error to the
    [statuscheck plugin][statuscheck], which will trigger agent process restart.
13. In case of a non-healing processing failure, an after-error Healing resync
    gets scheduled to execute soon after.

### Event logging

Every processed event is logged into the standard output with two messages - first
introducing a newly received event and the second summarizing the outcome of the
event processing once it has finalized. Both messages are bordered using brackets
and asterisks for better readability, with the introduction log messages marked
using angle brackets pointing from the left to the right, to represent
incoming event, and the closing message using brackets oriented in the opposite
direction to denote the end of the event loop iteration.

An example event log:
```
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
*   NEW EVENT: Add Pod kube-system/coredns-78fcdf6894-k5sd4                                                                   #2 *
*              * Container: 740ee06ac2bc0843291614f4d8348e2a61d78b1ee1681b07a52eff63930ccb6e                                     *
*              * Network namespace: /proc/25738/ns/net                                                                           *
*   EVENT HANDLERS: podmanager, ipv4net, service                                                                                 *
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

// here would be logs from event handlers, transaction log

<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
*   FINALIZED EVENT: Add Pod kube-system/coredns-78fcdf6894-k5sd4                                                             #2 *
*   HANDLED BY: podmanager, ipv4net, service                                                                          took 723ms *
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
```

The introduction message prints event name (given by `GetName()` method),
followed by event description (given by `String()`), respecting new line
characters and potentially splitting the description into even more lines
to avoid border overflow. Next the chain of event handlers planned to be called
for the event is listed. The closing message prints how the event processing
actually went, potentially listing errors if any occurred and the total execution
time.

Processed events are sequenced with unsigned 64bit integers, where 0 is given
to the first event, which is guaranteed to be the startup resync. The event
sequence number is displayed in both opening and closing messages, aligned
to the right side of the message box and prefixed with the hash symbol.

### Event history

The Controller plugin maintains an in-memory history of processed events.
Every finalized event is recorded as an instance of the `EventRecord` type:

```
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
```

Event payload is not fully recorded, however, only the event name, description,
return values from event handlers and the associated transaction that was
submitted to VPP-Agent.

The records are not kept in-memory forever, however, otherwise the memory usage
would grow indefinitely. Instead the history is periodically trimmed off
too old records. Maximum allowed age of records can be configured, by default
it is 24 hours.

The event history is exposed via [REST API][controller-rest].

[external-config-guide]: EXTERNAL_CONFIG.md
[event-loop-diagram]: event-loop/event-loop.png
[controller-config]: CORE_PLUGINS.md#controller-configuration
[controller-rest]: CORE_PLUGINS.md#rest-api
[controller-caches]: CORE_PLUGINS.md#input-data-caching
[controller-plugin]: https://github.com/contiv/vpp/blob/master/plugins/controller/plugin_controller.go
[controller-api]: https://github.com/contiv/vpp/tree/master/plugins/controller/api
[controller-el-api]: https://github.com/contiv/vpp/blob/master/plugins/controller/api/event_loop.go
[controller-db-api]: https://github.com/contiv/vpp/blob/master/plugins/controller/api/db.go
[controller-txn-api]: https://github.com/contiv/vpp/blob/master/plugins/controller/api/txn.go
[controller-error-api]: https://github.com/contiv/vpp/blob/master/plugins/controller/api/error.go
[controller-healing-api]: https://github.com/contiv/vpp/blob/master/plugins/controller/api/healing.go
[controller-impl]: https://github.com/contiv/vpp/blob/master/plugins/controller/plugin_controller.go
[ligato-vpp-agent]: http://github.com/ligato/vpp-agent
[podmanager]: https://github.com/contiv/vpp/tree/master/plugins/podmanager
[podmanager-api]: https://github.com/contiv/vpp/blob/master/plugins/podmanager/podmanager_api.go
[nodesync]: https://github.com/contiv/vpp/tree/master/plugins/nodesync
[statuscheck]: https://github.com/ligato/cn-infra/tree/master/health/statuscheck
[db-resources]: https://github.com/contiv/vpp/tree/master/dbresources
