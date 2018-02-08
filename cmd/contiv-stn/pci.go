package main

import (
	"fmt"
	"log"
	"os"
)

const (
	pciBindFile     = "/sys/bus/pci/drivers/%s/bind"
	pciUnbindFile   = "/sys/bus/pci/devices/%s/driver/unbind"
	pciPresenceFile = "/sys/bus/pci/drivers/%s/%s"
)

// pciDriverBind binds the PCI device to specified driver.
func pciDriverBind(pciAddr string, driver string) error {

	// check if not bound already
	if pciBoundToDriver(pciAddr, driver) {
		log.Printf("%s already bound to driver %s", pciAddr, driver)
		return nil
	}

	// first unbind from the current driver
	pciDriverUnbind(pciAddr) // do not care about error (it may be unbound already)

	log.Printf("Binding %s to driver %s", pciAddr, driver)

	// bind by writing to proper file
	err := pciAddrWriteToFile(fmt.Sprintf(pciBindFile, driver), pciAddr)

	return err
}

// pciDriverUnbind unbinds the PCI device from existing driver.
func pciDriverUnbind(pciAddr string) error {
	log.Printf("Unbinding %s from its current driver", pciAddr)

	// unbind by writing to proper file
	err := pciAddrWriteToFile(fmt.Sprintf(pciUnbindFile, pciAddr), pciAddr)

	return err
}

// pciBoundToDriver returns true in case the PCI device is bound to the specified driver, false otherwise.
func pciBoundToDriver(pciAddr string, driver string) bool {
	// check presence of pciPresenceFile
	if _, err := os.Stat(fmt.Sprintf(pciPresenceFile, driver, pciAddr)); err == nil {
		return true
	}
	return false
}

// pciAddrWriteToFile writes PCI address into the specified file.
// It can be used to bind or unbind a PCI device to/from its driver.
func pciAddrWriteToFile(fileName string, pciAddr string) error {

	// try opening the file
	f, err := os.OpenFile(fileName, os.O_WRONLY, os.ModePerm)
	if err != nil {
		log.Printf("Error by opening %s: %v", fileName, err)
		return err
	}
	defer f.Close()

	// write PCI address to bind/unbind
	_, err = f.Write([]byte(pciAddr))
	if err != nil {
		log.Printf("Error by writing to %s: %v", fileName, err)
		return err
	}

	return nil
}
