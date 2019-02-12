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

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/ghodss/yaml"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

const (
	k8sURLPrefix = "/api/k8s/"
	contivPrefix = "/api/contiv/"

	serviceToken = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	rootCa       = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// Config group configurable parameters of contiv-ui backend
type Config struct {
	// Port where backend API is exposed
	Port int
	// Basic auth is map of valid credentials user-> pass
	// required for backend. If empty basic auth is disabled.
	BasicAuth map[string]string
	// ServerCrt filename of certificate used to secure the backend endpoint.
	// If not empty backend is exposed using HTTPS instead of HTTP.
	ServerCrt string
	// ServerKey key corresponding to serverCrt
	ServerKey string

	// ContivHTTPSEnabled flag denoting whether HTTPS should be used
	ContivHTTPSEnabled bool
	// ContivBasicAuthUser defines user for basic auth while accessing Contiv API
	ContivBasicAuthUser string
	// ContivBasicAuthPass defines pass for basic auth while accessing Contiv API
	ContivBasicAuthPass string
	// ContivCA is CA used to validate contiv server cert
	ContivCA string
	// ContivInsecureSkipVerify flag denoting whether server cert should be validated
	ContivInsecureSkipVerify bool
	// ContivPort is port where Contiv API is exposed
	ContivPort int
}

type proxy struct {
	// k8sHost is host where requests to kubernetes API are sent
	k8sHost string
	// k8sPort is host where requests to kubernetes API are sent
	k8sPort string
	// k8sToken is appended to all requests targeting kubernetes API
	k8sToken string
	// k8sClient http client sending requests to k8s API
	k8sClient *http.Client
	// contivClient http client sending requests to contiv API
	contivClient *http.Client
	*Config
}

// UseHTTPS returns true if the endpoint is configured to use server cert
func (c *Config) UseHTTPS() bool {
	if c.ServerCrt == "" || c.ServerKey == "" {
		return false
	}
	return true
}

// IsBasicAuthOK return if credentials matches configured couples login:pass
// or if basic auth is disabled (empty map)
func (c *Config) IsBasicAuthOK(w http.ResponseWriter, r *http.Request) bool {
	if len(c.BasicAuth) == 0 {
		return true
	}
	user, pass, ok := r.BasicAuth()
	if ok {
		p, exists := c.BasicAuth[user]
		if exists && p == pass {
			// valid credentials
			return true
		}
	}

	w.Header().Set("WWW-Authenticate", "Provide valid username and password")
	http.Error(w, "Unauthorized.", http.StatusUnauthorized)

	return false
}

func writeServerError(err error, w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(err.Error()))
}

// k8sHandler proxies requests to kubernetes API server
// the handler trims '/k8s/' from received url path and sends a request
// with the trimmed path to k8s
func (p *proxy) k8sHandler(w http.ResponseWriter, r *http.Request) {
	ok := p.IsBasicAuthOK(w, r)
	if !ok {
		return
	}

	url := fmt.Sprintf("https://%v:%v/%v", p.k8sHost, p.k8sPort, strings.TrimPrefix(r.URL.Path, k8sURLPrefix))

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		writeServerError(err, w, r)
		return
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %v", p.k8sToken))
	resp, err := p.k8sClient.Do(req)
	if err != nil {
		writeServerError(err, w, r)
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

func (p *proxy) contivHandler(w http.ResponseWriter, r *http.Request) {
	ok := p.IsBasicAuthOK(w, r)
	if !ok {
		return
	}
	vswitch := r.URL.Query().Get("vswitch")
	if vswitch == "" {
		vswitch = "127.0.0.1"
	}
	protocol := "http"
	if p.ContivHTTPSEnabled {
		protocol = "https"
	}
	url := fmt.Sprintf("%v://%v:%v/%v", protocol, vswitch, p.ContivPort, strings.TrimPrefix(r.URL.Path, contivPrefix))

	req, err := http.NewRequest(r.Method, url, r.Body)
	if err != nil {
		writeServerError(err, w, r)
		return
	}

	if p.ContivBasicAuthUser != "" && p.ContivBasicAuthPass != "" {
		req.SetBasicAuth(p.ContivBasicAuthUser, p.ContivBasicAuthPass)
	}

	resp, err := p.contivClient.Do(req)
	if err != nil {
		writeServerError(err, w, r)
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(body)

}

func loadConfig(fileName string) (cfg *Config, err error) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	err = yaml.Unmarshal(data, c)
	return c, err
}

func initProxy() (s *proxy, err error) {
	cfg, err := loadConfig(os.Getenv("CONTIV_UI_CONF"))
	if err != nil {
		return nil, err
	}
	log.Printf("CFG: %+v\n", cfg)
	s = &proxy{
		k8sPort: os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS"),
		k8sHost: os.Getenv("KUBERNETES_SERVICE_HOST"),
		Config:  cfg,
	}

	// load certificate bundle for api proxy verification
	cert, err := ioutil.ReadFile(rootCa)
	if err != nil {
		return nil, fmt.Errorf("couldn't load root CA %v", err)
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(cert)

	s.k8sClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
	}

	s.contivClient = &http.Client{}

	if s.ContivInsecureSkipVerify {
		s.contivClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	} else if s.ContivCA != "" {
		ca, err := ioutil.ReadFile(s.ContivCA)
		if err != nil {
			return nil, fmt.Errorf("couldn't load contiv CA %v", err)
		}

		contivCertPool := x509.NewCertPool()
		contivCertPool.AppendCertsFromPEM(ca)
		s.contivClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: contivCertPool,
			},
		}
	}

	// load authentication k8sToken for requests
	t, err := ioutil.ReadFile(serviceToken)
	if err != nil {
		return nil, fmt.Errorf("unable to read k8sToken %v", err)
	}
	s.k8sToken = string(t)

	return s, nil
}

func main() {
	p, err := initProxy()
	if err != nil {
		log.Fatal(err)
	}
	uiPaths := []string{"/kubernetes/nodes", "/bridge-domain", "/services", "/contiv"}
	fs := http.FileServer(http.Dir("static/"))
	http.Handle("/", fs)
	for _, p := range uiPaths {
		http.Handle(p, http.StripPrefix(p, fs))
	}
	http.HandleFunc(k8sURLPrefix, p.k8sHandler)
	http.HandleFunc(contivPrefix, p.contivHandler)

	if p.UseHTTPS() {
		log.Printf("Listening at https://localhost:%v", p.Port)
		http.ListenAndServeTLS(fmt.Sprintf(":%v", p.Port), p.ServerCrt, p.ServerKey, nil)
	} else {
		log.Printf("Listening at http://localhost:%v", p.Port)
		http.ListenAndServe(fmt.Sprintf(":%v", p.Port), nil)
	}

}
