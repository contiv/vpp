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
	"net/http"

	"github.com/unrolled/render"

	"github.com/ligato/cn-infra/rpc/rest"
)

const (
	// prefix used for REST urls of the controller.
	urlPrefix = "/controller/"

	// eventHistoryURL is URL used to obtain the event history.
	eventHistoryURL = urlPrefix + "event-history"

	// resyncURL is URL used to trigger DB resync.
	resyncURL = urlPrefix + "resync"
)

// errorString wraps string representation of an error that, unlike the original
// error, can be marshalled.
type errorString struct {
	Error string
}

// registerHandlers registers all supported REST APIs.
func (c *Controller) registerHandlers(http rest.HTTPHandlers) {
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
