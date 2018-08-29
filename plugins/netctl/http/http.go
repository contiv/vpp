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
//

package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

//GetNodeInfo will make an http request for the given command and return an indented slice of bytes.
func GetNodeInfo(ipAddr string, cmd string) []byte {
	client := http.Client{
		Transport:     nil,
		CheckRedirect: nil,
		Jar:           nil,
		Timeout:       30000000,
	}
	url := fmt.Sprintf("http://%s:9999/%s", ipAddr, cmd)
	res, err := client.Get(url)
	if err != nil {
		err := fmt.Errorf("getNodeInfo: url: %s cleintGet Error: %s", url, err.Error())
		fmt.Printf("http get error: %s ", err.Error())
		return nil
	} else if res.StatusCode < 200 || res.StatusCode > 299 {
		err := fmt.Errorf("getNodeInfo: url: %s HTTP res.Status: %s", url, res.Status)
		fmt.Printf("http get error: %s ", err.Error())
		return nil
	}
	b, _ := ioutil.ReadAll(res.Body)
	b = []byte(b)
	var out bytes.Buffer
	err = json.Indent(&out, b, "", "  ")
	if err != nil {
		fmt.Printf(err.Error())
	}
	return out.Bytes()
}
