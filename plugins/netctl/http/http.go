package http

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"bytes"
	"encoding/json"
)

func GetNodeInfo(ipAddr string, cmd string) []byte {
	client := http.Client{
		Transport:     nil,
		CheckRedirect: nil,
		Jar:           nil,
		Timeout:       30000000000000,
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
	err = json.Indent(&out,b,"","  ")
	if err != nil {
		fmt.Printf(err.Error())
	}

	if err != nil {
		errString := fmt.Sprintf("Error unmarshaling data for ip %+v: %+v", ipAddr, err)
		fmt.Printf(errString)
	}
	return out.Bytes()
}
