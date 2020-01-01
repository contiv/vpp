/*
 * // Copyright (c) 2018 Cisco and/or its affiliates.
 * //
 * // Licensed under the Apache License, Version 2.0 (the "License");
 * // you may not use this file except in compliance with the License.
 * // You may obtain a copy of the License at:
 * //
 * //     http://www.apache.org/licenses/LICENSE-2.0
 * //
 * // Unless required by applicable law or agreed to in writing, software
 * // distributed under the License is distributed on an "AS IS" BASIS,
 * // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * // See the License for the specific language governing permissions and
 * // limitations under the License.
 */

package utils

import (
	"context"
	"encoding/json"
	"github.com/unrolled/render"
	"io/ioutil"
	"net/http"
	"os/exec"
	"time"
)

const (
	defaultNetctlCommandTimeout = 2 * time.Second
)

// HandleNetctlCommand executes the contiv-netctl tool with give arguments and sends the output in the response.
func HandleNetctlCommand(formatter *render.Render) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		defer req.Body.Close()
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		var args []string
		err = json.Unmarshal(body, &args)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), defaultNetctlCommandTimeout)
		defer cancel()

		out, err := exec.CommandContext(ctx, "/contiv-netctl", args...).CombinedOutput()
		w.Write(out)
		if err != nil {
			w.Write([]byte(err.Error()))
		}
	}
}
