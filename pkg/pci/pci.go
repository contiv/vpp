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

package pci

import (
	"fmt"
	"log"
	"os"
	"strings"
)

const (
	sysBusPCI           = "/sys/bus/pci"
	pciDevVendorFile    = sysBusPCI + "/devices/%s/vendor"
	pciDevIDFile        = sysBusPCI + "/devices/%s/device"
	pciDriverNewDevFile = sysBusPCI + "/drivers/%s/new_id"
	pciDriverBindFile   = sysBusPCI + "/drivers/%s/bind"
	pciDevUnbindFile    = sysBusPCI + "/devices/%s/driver/unbind"
	pciDriverDir        = sysBusPCI + "/drivers/%s"
	pciDriverDevDir     = pciDriverDir + "/%s"
)

const (
	maxReadSize = 1024
)

// DriverBind binds the PCI device to specified driver.
func DriverBind(pciAddr string, driver string) error {

	// check if the driver is loaded
	if !fileExists(fmt.Sprintf(pciDriverDir, driver)) {
		log.Printf("%s driver is not loaded", driver)
		return fmt.Errorf("%s driver is not loaded", driver)
	}

	// check if not already bound to the specified driver
	if fileExists(fmt.Sprintf(pciDriverDevDir, driver, pciAddr)) {
		log.Printf("%s already bound to the driver %s", pciAddr, driver)
		return nil
	}

	// first unbind from the current driver
	DriverUnbind(pciAddr) // do not care about error (it may be unbound already)

	log.Printf("Binding %s to driver %s", pciAddr, driver)

	var vendor, devID uint32

	// get vendor ID
	vendorStr, err := readFromFileFile(fmt.Sprintf(pciDevVendorFile, pciAddr))
	if err != nil {
		log.Println(err)
		return err
	}
	fmt.Sscanf(vendorStr, "0x%x", &vendor)

	// get device ID
	devIDStr, err := readFromFileFile(fmt.Sprintf(pciDevIDFile, pciAddr))
	if err != nil {
		log.Println(err)
		return err
	}
	fmt.Sscanf(devIDStr, "0x%x", &devID)

	// enable device in the driver
	err = writeToFile(fmt.Sprintf(pciDriverNewDevFile, driver),
		fmt.Sprintf("%4x %4x", vendor, devID))
	if err != nil {
		log.Printf("(non-fatal) %s", err)
		// do not return an error here, on some systems it returns an error even if it actually works
	}

	// bind by writing to proper file
	err = writeToFile(fmt.Sprintf(pciDriverBindFile, driver), pciAddr)
	if err != nil {
		log.Printf("(non-fatal) %s", err)
		// do not return an error here, on some systems it returns an error even if it actually works
	}

	return nil
}

// DriverUnbind unbinds the PCI device from existing driver.
func DriverUnbind(pciAddr string) error {
	log.Printf("Unbinding %s from its current driver", pciAddr)

	// unbind by writing to proper file
	err := writeToFile(fmt.Sprintf(pciDevUnbindFile, pciAddr), pciAddr)
	if err != nil {
		log.Println(err)
	}

	return err
}

// fileExists returns true in case the provided file exists, false otherwise.
func fileExists(file string) bool {
	// check presence of pciDriverDevDir
	if _, err := os.Stat(file); err == nil {
		return true
	}
	return false
}

// readFromFileFile reads string from the specified file.
func readFromFileFile(fileName string) (string, error) {

	// try opening the file
	f, err := os.OpenFile(fileName, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return "", fmt.Errorf("error by opening %s: %v", fileName, err)
	}
	defer f.Close()

	// read from file
	buf := make([]byte, maxReadSize)
	_, err = f.Read(buf)
	if err != nil {
		return "", fmt.Errorf("error by reading from %s: %v", fileName, err)
	}

	return strings.TrimSpace(fmt.Sprintf("%s", buf)), nil
}

// writeToFile writes string into the specified file.
func writeToFile(fileName string, content string) error {

	log.Printf("Writing '%s' into file %s", content, fileName)

	// try opening the file
	f, err := os.OpenFile(fileName, os.O_WRONLY, os.ModePerm)
	if err != nil {
		return fmt.Errorf("error by opening %s: %v", fileName, err)
	}
	defer f.Close()

	// write to file
	_, err = f.Write([]byte(content))
	if err != nil {
		return fmt.Errorf("error by writing to %s: %v", fileName, err)
	}

	return nil
}
