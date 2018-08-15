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

package datastore

import (
	"fmt"
	"github.com/ligato/cn-infra/logging"
	"io"
	"os"
	"time"
)

// SimpleReport holds error/warning messages recorded during data collection /
// validation
type SimpleReport struct {
	Log       logging.Logger
	Data      map[string][]string
	Output    io.Writer
	TimeStamp time.Time
}

// NewSimpleReport creates a new SimpleReport instance
func NewSimpleReport(log logging.Logger) *SimpleReport {
	return &SimpleReport{
		Log:    log,
		Data:   make(map[string][]string),
		Output: os.Stdout,
	}
}

// LogErrAndAppendToNodeReport log an error and appends the string to
// the status log
func (r *SimpleReport) LogErrAndAppendToNodeReport(nodeName string, errString string) {
	r.AppendToNodeReport(nodeName, errString)
	r.Log.Errorf(errString)
}

// AppendToNodeReport appends the string to the status log
func (r *SimpleReport) AppendToNodeReport(nodeName string, errString string) {
	if r.Data[nodeName] == nil {
		r.Data[nodeName] = make([]string, 0)
	}
	r.Data[nodeName] = append(r.Data[nodeName], errString)
}

// Clear clears the status log
func (r *SimpleReport) Clear() {
	r.Data = make(map[string][]string)
}

// Print prints the status log
func (r *SimpleReport) Print() {
	fmt.Fprintln(r.Output, "Error Report:")
	fmt.Fprintln(r.Output, "Time-stamp:", r.GetTimeStamp())
	fmt.Fprintln(r.Output, "=============")
	for k, rl := range r.Data {
		fmt.Fprintf(r.Output, "Key: %s\n", k)
		for i, line := range rl {
			fmt.Fprintf(r.Output, "  %d: %s\n", i, line)
		}
		fmt.Fprintln(r.Output)
	}
}

func (r *SimpleReport) SetTimeStamp(time time.Time) {
	r.TimeStamp = time
}

func (r *SimpleReport) GetTimeStamp() time.Time {
	return r.TimeStamp
}
