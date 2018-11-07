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

package remote

import (
	"bytes"
	"fmt"
	"github.com/ligato/cn-infra/config"
	"golang.org/x/net/html"
	"net/http"
	"os"
	"strings"
	"time"
)

// HTTPClient wraps http.Client with configured authorization and url base
type HTTPClient struct {
	// Config for this client
	Config *HTTPClientConfig

	http *http.Client
	base string
}

// HTTPClientConfig is configuration for http client
type HTTPClientConfig struct {
	// Port on what targets are listening on
	Port string `json:"port"`
	// Basic authorization for client
	BasicAuth string `json:"basic-auth"`
	// If https or http should be used
	UseHTTPS bool `json:"use-https"`
}

// CreateHTTPClient uses environment variable HTTP_CONFIG or HTTP config file to establish connection
func CreateHTTPClient(configFile string) (*HTTPClient, error) {
	if configFile == "" {
		configFile = os.Getenv("HTTP_CLIENT_CONFIG")
	}

	cfg := &HTTPClientConfig{}
	if configFile != "" {
		if err := config.ParseConfigFromYamlFile(configFile, cfg); err != nil {
			return nil, err
		}
	}

	transport := &http.Transport{}

	http := &http.Client{
		Transport:     transport,
		Timeout:       10 * time.Second,
		CheckRedirect: nil,
		Jar:           nil,
	}

	return &HTTPClient{
		Config: cfg,
		http:   http,
	}, nil
}

// Helper function to create url from config
func (client *HTTPClient) createURL(base string, cmd string) string {
	// Use either http or https
	url := "http://"
	if client.Config.UseHTTPS {
		url = "https://"
	}

	// Add port as suffix
	url = url + base + ":" + client.Config.Port

	// Append command
	url = url + "/" + cmd
	return url
}

// Get creates http get request prefixing cmd with base if needed and using correct authentication
func (client *HTTPClient) Get(base string, cmd string) (*http.Response, error) {
	url := client.createURL(base, cmd)
	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return nil, err
	}

	if len(client.Config.BasicAuth) > 0 {
		fields := strings.Split(client.Config.BasicAuth, ":")
		if len(fields) != 2 {
			return nil, fmt.Errorf("invalid format of basic auth entry '%v' expected 'user:pass'", client.Config.BasicAuth)
		}
		req.SetBasicAuth(fields[0], fields[1])
	}

	return client.http.Do(req)
}

// Post creates http post request prefixing cmd with base if needed and using correct authentication
func (client *HTTPClient) Post(base string, cmd string, body string) (*http.Response, error) {
	url := client.createURL(base, cmd)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(body)))
	req.Header.Set("Content-Type", "application/json")

	if err != nil {
		return nil, err
	}

	if len(client.Config.BasicAuth) > 0 {
		fields := strings.Split(client.Config.BasicAuth, ":")
		if len(fields) != 2 {
			return nil, fmt.Errorf("invalid format of basic auth entry '%v' expected 'user:pass'", client.Config.BasicAuth)
		}
		req.SetBasicAuth(fields[0], fields[1])
	}

	return client.http.Do(req)
}

// Helper function to pull the href attribute from a Token
func getHref(t html.Token) (ok bool, href string) {
	// Iterate over all of the Token's attributes until we find an "href"
	for _, a := range t.Attr {
		if a.Key == "href" {
			href = a.Val
			ok = true
		}
	}
	// "bare" return will return the variables (ok, href) as defined in
	// the function definition
	return
}

// Crawl extracts all http** links from a given webpage (suffix default is
func (client *HTTPClient) Crawl(base string, cmd string, suffix string) []string {
	resp, err := client.Get(base, cmd)
	urlSlice := make([]string, 0)
	if err != nil {
		fmt.Println("ERROR: Failed to crawl \"" + suffix + "\"")
		return []string{}
	}
	b := resp.Body
	defer b.Close() // close Body when the function returns
	z := html.NewTokenizer(b)
	for {
		tt := z.Next()
		switch {
		case tt == html.ErrorToken:
			// End of the document, we're done
			return urlSlice
		case tt == html.StartTagToken:
			t := z.Token()
			// Check if the token is an <a> tag
			isAnchor := t.Data == "a"
			if !isAnchor {
				continue
			}
			// Extract the href value, if there is one
			ok, url := getHref(t)
			if !ok {
				continue
			}
			// Make sure the url begines in http**
			hasProto := strings.Index(url, suffix) == 0
			if hasProto {
				urlSlice = append(urlSlice, url)
			}
		}
	}
}
