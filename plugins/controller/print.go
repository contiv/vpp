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
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/contiv/vpp/plugins/controller/api"
)

// printNewEvent prints a banner into stdout about a newly received event.
func (c *Controller) printNewEvent(eventRec *EventRecord, handlers []api.EventHandler) {
	var buf strings.Builder

	border := strings.Repeat(">", 130) + "\n"
	buf.WriteString(border)

	evDescLns := strings.Split(eventRec.Description, "\n")
	evDescLns = splitLongLines(evDescLns, 110, 6)
	headline := "NEW EVENT"
	if eventRec.IsFollowUp {
		headline += fmt.Sprintf(" (follow-up to %s)", eventSeqNumToStr(eventRec.FollowUpTo))
	}
	headline += ": "
	buf.WriteString(fmt.Sprintf("*   %-113s %10s *\n",
		headline+evDescLns[0], eventSeqNumToStr(eventRec.SeqNum)))
	for i := 1; i < len(evDescLns); i++ {
		buf.WriteString(fmt.Sprintf("*              %-113s *\n", evDescLns[i]))
	}

	if len(handlers) > 0 {
		buf.WriteString(fmt.Sprintf("*   EVENT HANDLERS: %-108s *\n", evHandlersToStr(handlers)))
	}

	buf.WriteString(border)
	fmt.Printf(buf.String())
}

// printNewEvent prints a banner into stdout about a finalized event.
func (c *Controller) printFinalizedEvent(eventRec *EventRecord) {
	var (
		buf        strings.Builder
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

	border := strings.Repeat("<", 130) + "\n"
	buf.WriteString(border)

	evDesc := strings.Split(eventRec.Description, "\n")[0]
	buf.WriteString(fmt.Sprintf("*   FINALIZED EVENT: %-96s %10s *\n",
		evDesc, eventSeqNumToStr(eventRec.SeqNum)))

	duration := fmt.Sprintf("took %v",
		eventRec.ProcessingEnd.Sub(eventRec.ProcessingStart).Round(time.Millisecond))
	if len(handledBy) > 0 {
		buf.WriteString(fmt.Sprintf("*   HANDLED BY: %-91s %20s *\n",
			strings.Join(handledBy, ", "), duration))
	}
	if len(handledBy) == 0 && eventRec.Txn != nil {
		buf.WriteString(fmt.Sprintf("*   HANDLED BY VPP-AGENT %103s *\n",
			duration))
	}

	if hasErrors {
		buf.WriteString(fmt.Sprintf("*   %-124s *\n", "ERRORS:"))
		for _, handlerRec := range eventRec.Handlers {
			if handlerRec.Error == nil {
				continue
			}
			var withRevert string
			if handlerRec.Revert {
				withRevert = " (REVERT)"
			}
			errorDesc := fmt.Sprintf("%s%s: %s",
				handlerRec.Handler, withRevert, handlerRec.Error)
			buf.WriteString(fmt.Sprintf("*       * %-118s *\n", errorDesc))
		}
	}

	if len(revertedBy) > 0 {
		buf.WriteString(fmt.Sprintf("*   REVERTED BY: %-111s *\n",
			strings.Join(revertedBy, ", ")))
	}

	if eventRec.TxnError != nil {
		buf.WriteString(fmt.Sprintf("*   TRANSACTION ERROR: %-105v *\n",
			eventRec.TxnError))
	}

	buf.WriteString(border)
	fmt.Printf(buf.String())
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
	return "#" + strconv.FormatUint(seqNum, 10)
}

// splitLongLines splits too long lines into multiple lines by space,
// each to the maximum allowed length.
func splitLongLines(lines []string, limit int, indent int) (splited []string) {
	for _, line := range lines {
		if len(line) <= limit {
			splited = append(splited, line)
			continue
		}

		words := strings.Split(line, " ")
		var (
			newLine  string
			newLines []string
		)
		for i := 0; i < len(words); i++ {
			word := words[i]

			// first word is added regardless of its length
			if newLine == "" {
				if len(newLines) > 0 {
					// indent added to newly introduced lines
					newLine += strings.Repeat(" ", indent)
				}
				newLine += word
				continue
			}

			// it newLine+word would overflow the limit -> start a new line
			wordLen := len(word) + 1 // + preceding space
			if len(newLine)+wordLen > limit {
				newLines = append(newLines, newLine)
				newLine = ""
				i-- // replay the word
				continue
			}

			newLine += " " + word
		}
		if newLine != "" {
			newLines = append(newLines, newLine)
		}
		splited = append(splited, newLines...)
	}
	return splited
}
