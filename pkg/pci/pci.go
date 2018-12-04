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
	pciVendorFile   = "/sys/bus/pci/devices/%s/vendor"
	pciDeviceIDFile = "/sys/bus/pci/devices/%s/device"
	pciNewIDFile    = "/sys/bus/pci/drivers/%s/new_id"
	pciBindFile     = "/sys/bus/pci/drivers/%s/bind"
	pciUnbindFile   = "/sys/bus/pci/devices/%s/driver/unbind"
	pciPresenceFile = "/sys/bus/pci/drivers/%s/%s"
)

const (
	maxReadSize = 1024
)

// DriverBind binds the PCI device to specified driver.
func DriverBind(pciAddr string, driver string) error {

	// check if not bound already
	if boundToDriver(pciAddr, driver) {
		log.Printf("%s already bound to driver %s", pciAddr, driver)
		return nil
	}

	// first unbind from the current driver
	DriverUnbind(pciAddr) // do not care about error (it may be unbound already)

	log.Printf("Binding %s to driver %s", pciAddr, driver)

	var vendor, devID uint32

	// get vendor ID
	vendorStr, err := readFromFileFile(fmt.Sprintf(pciVendorFile, pciAddr))
	if err != nil {
		log.Println(err)
		return err
	}
	fmt.Sscanf(vendorStr, "0x%x", &vendor)

	// get device ID
	devIDStr, err := readFromFileFile(fmt.Sprintf(pciDeviceIDFile, pciAddr))
	if err != nil {
		log.Println(err)
		return err
	}
	fmt.Sscanf(devIDStr, "0x%x", &devID)

	// enable device in the driver
	err = writeToFile(fmt.Sprintf(pciNewIDFile, driver),
		fmt.Sprintf("%x %x", vendor, devID))
	if err != nil {
		log.Println(err)
		return err
	}

	// bind by writing to proper file
	err = writeToFile(fmt.Sprintf(pciBindFile, driver), pciAddr)
	if err != nil {
		log.Println(err)
		return err
	}

	return nil
}

// DriverUnbind unbinds the PCI device from existing driver.
func DriverUnbind(pciAddr string) error {
	log.Printf("Unbinding %s from its current driver", pciAddr)

	// unbind by writing to proper file
	err := writeToFile(fmt.Sprintf(pciUnbindFile, pciAddr), pciAddr)

	return err
}

// boundToDriver returns true in case the PCI device is bound to the specified driver, false otherwise.
func boundToDriver(pciAddr string, driver string) bool {
	// check presence of pciPresenceFile
	if _, err := os.Stat(fmt.Sprintf(pciPresenceFile, driver, pciAddr)); err == nil {
		return true
	}
	return false
}

// readFromFileFile reads string from the specified file.
func readFromFileFile(fileName string) (string, error) {

	// try opening the file
	f, err := os.OpenFile(fileName, os.O_RDONLY, os.ModePerm)
	if err != nil {
		log.Printf("Error by opening %s: %v", fileName, err)
		return "", err
	}
	defer f.Close()

	// read from file
	buf := make([]byte, maxReadSize)
	_, err = f.Read(buf)
	if err != nil {
		log.Printf("Error by reading from %s: %v", fileName, err)
		return "", err
	}

	return strings.TrimSpace(fmt.Sprintf("%s", buf)), nil
}

// writeToFile writes string into the specified file.
func writeToFile(fileName string, content string) error {

	log.Printf("Writing '%s' into file %s", content, fileName)

	// try opening the file
	f, err := os.OpenFile(fileName, os.O_WRONLY, os.ModePerm)
	if err != nil {
		log.Printf("Error by opening %s: %v", fileName, err)
		return err
	}
	defer f.Close()

	// write to file
	_, err = f.Write([]byte(content))
	if err != nil {
		log.Printf("Error by writing to %s: %v", fileName, err)
		return err
	}

	return nil
}
