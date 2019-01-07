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
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/unrolled/render"
)

const (
	// prefix used for REST urls of the controller.
	urlPrefix = "/controller/"

	// eventHistoryURL is URL used to obtain the event history.
	eventHistoryURL = urlPrefix + "event-history"

	// event-history arguments (by precedence):
	//   * seq-num
	//   * since - until (Unix timestamps)
	//   * from - to (sequence numbers)
	//   * first (max. number of oldest records to return)
	//   * last (max. number of latest records to return)
	seqNumArg = "seq-num"
	sinceArg  = "since"
	untilArg  = "until"
	fromArg   = "from"
	toArg     = "to"
	firstArg  = "first"
	lastArg   = "last"

	// resyncURL is URL used to trigger DB resync.
	resyncURL = urlPrefix + "resync"
)

// errorString wraps string representation of an error that, unlike the original
// error, can be marshalled.
type errorString struct {
	Error string
}

// registerHandlers registers all supported REST APIs.
func (c *Controller) registerHandlers() {
	if c.HTTPHandlers == nil {
		c.Log.Warn("No http handler provided, skipping registration of Controller REST handlers")
		return
	}
	c.HTTPHandlers.RegisterHTTPHandler(eventHistoryURL, c.eventHistoryGetHandler, "GET")
	c.HTTPHandlers.RegisterHTTPHandler(resyncURL, c.resyncReqHandler, "POST")
}

// eventHistoryGetHandler is the GET handler for "event-history" API.
func (c *Controller) eventHistoryGetHandler(formatter *render.Render) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		c.historyLock.Lock()
		defer c.historyLock.Unlock()

		timeParams := make(map[string]time.Time)
		intParams := make(map[string]int)
		args := req.URL.Query()

		// parse optional integer parameters
		for _, intParam := range []string{seqNumArg, fromArg, toArg, firstArg, lastArg} {
			if param, withParam := args[intParam]; withParam && len(param) == 1 {
				value, err := strconv.Atoi(param[0])
				if err != nil {
					formatter.JSON(w, http.StatusInternalServerError, errorString{err.Error()})
					return
				}
				intParams[intParam] = value
			}
		}

		// parse optional time parameters
		for _, timeParam := range []string{sinceArg, untilArg} {
			if param, withParam := args[timeParam]; withParam && len(param) == 1 {
				value, err := stringToTime(param[0])
				if err != nil {
					formatter.JSON(w, http.StatusInternalServerError, errorString{err.Error()})
					return
				}
				timeParams[timeParam] = value
			}
		}

		// handle seq-num argument
		if seqNum, hasSeqNum := intParams[seqNumArg]; hasSeqNum {
			var evRecord *EventRecord
			for _, event := range c.eventHistory {
				if event.SeqNum == uint64(seqNum) {
					evRecord = event
					break
				}
			}
			if evRecord == nil {
				err := errors.New("event with such sequence number is not recorded")
				formatter.JSON(w, http.StatusNotFound, errorString{err.Error()})
				return
			}
			formatter.JSON(w, http.StatusOK, evRecord)
			return
		}

		// handle *since-until* arguments
		since, hasSince := timeParams[sinceArg]
		until, hasUntil := timeParams[untilArg]
		if hasSince || hasUntil {
			evHistory := c.getEventHistory(since, until)
			formatter.JSON(w, http.StatusOK, evHistory)
			return
		}

		// handle *from-to* arguments
		from, hasFrom := intParams[fromArg]
		to, hasTo := intParams[toArg]
		if hasFrom && hasTo {
			var evHistory []*EventRecord
			for _, event := range c.eventHistory {
				if event.SeqNum >= uint64(from) && event.SeqNum <= uint64(to) {
					evHistory = append(evHistory, event)
				}
			}
			formatter.JSON(w, http.StatusOK, evHistory)
			return
		}

		// handle *first* argument
		if first, hasFirst := intParams[firstArg]; hasFirst {
			historyLen := len(c.eventHistory)
			if historyLen < first {
				first = historyLen
			}
			formatter.JSON(w, http.StatusOK, c.eventHistory[:first])
			return
		}

		// handle *last* argument
		if last, hasLast := intParams[lastArg]; hasLast {
			historyLen := len(c.eventHistory)
			if historyLen < last {
				last = historyLen
			}
			formatter.JSON(w, http.StatusOK, c.eventHistory[historyLen-last:])
			return
		}

		// full history
		formatter.JSON(w, http.StatusOK, c.eventHistory)
	}
}

// resyncReqHandler is the POST handler for "resync" API.
func (c *Controller) resyncReqHandler(formatter *render.Render) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		err := c.dbWatcher.requestResync(false)
		if err != nil {
			formatter.JSON(w, http.StatusInternalServerError, errorString{err.Error()})
			return
		}
		formatter.JSON(w, http.StatusOK, "Resync request was successfully dispatched.")
	}
}

// stringToTime converts Unix timestamp from string to time.Time.
func stringToTime(s string) (time.Time, error) {
	sec, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(sec, 0), nil
}
