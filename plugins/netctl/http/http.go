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
	"time"
)

const defaultPort = ":9999"

//GetNodeInfo will make an http request for the given command and return an indented slice of bytes.
func GetNodeInfo(ipAddr string, cmd string) ([]byte, error) {
	client := http.Client{
		Transport:     nil,
		CheckRedirect: nil,
		Jar:           nil,
		Timeout:       10 * time.Second,
	}

	url := fmt.Sprintf("http://%s"+defaultPort+"/%s", ipAddr, cmd)
	res, err := client.Get(url)
	if err != nil {
		err := fmt.Errorf("getNodeInfo: url: %s cleintGet Error: %s", url, err.Error())
		fmt.Printf("http get error: %s ", err.Error())
		return nil, err
	} else if res.StatusCode < 200 || res.StatusCode > 299 {
		err := fmt.Errorf("getNodeInfo: url: %s HTTP res.Status: %s", url, res.Status)
		fmt.Printf("http get error: %s ", err.Error())
		return nil, err
	}

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	err = json.Indent(&out, b, "", "  ")
	return out.Bytes(), err
}

//SetNodeInfo will make an http json post request to get the vpp cli command output
func SetNodeInfo(ipAddr string, cmd string, body string) error {
	client := http.Client{
		Transport:     nil,
		CheckRedirect: nil,
		Jar:           nil,
		Timeout:       10 * time.Second,
	}

	url := fmt.Sprintf("http://%s"+defaultPort+"/%s", ipAddr, cmd)
	res, err := client.Post(url, "application/json", bytes.NewBuffer([]byte(body)))
	if err != nil {
		err := fmt.Errorf("SetNodeInfo: url: %s cleintGet Error: %s", url, err.Error())
		return err
	} else if res.StatusCode < 200 || res.StatusCode > 299 {
		err := fmt.Errorf("SetNodeInfo: url: %s HTTP res.Status: %s", url, res.Status)
		return err
	}
	b, _ := ioutil.ReadAll(res.Body)
	fmt.Println(string(b))
	return nil

}
