// Package ldpreload-label-injector contains tool for injecting ldpreload-specific labels into kubernetes yaml files
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

var (
	// command line flags
	inputFile     = flag.String("f", "", "Input file")
	outputFile    = flag.String("o", "", "Output file")
	help          = flag.Bool("h", false, "Switch to show help")
	useDebugLabel = flag.Bool("d", false, "Switch to used debug ldpreload label")
	proxyName     = flag.String("p", "", "Name of proxy container that should be used")
)

// injectParams pass important information from command line flags to injector
type injectParams struct {
	useDebugLabel bool
	proxyName     string
}

const helpContent = `ldpreload-label-injector injects ldpreload labels to kubernetes yaml files.
Usage:
  ldpreload-label-injector [input file]

Flags:
  -o [output file]  Sets output for modified kubernetes yaml file. This overrides default behaviour that takes input file as output file and modifies input file in-place.
  -d                Adds ldpreload debug label to yaml kubernetes files
  -p                Sets the name of container that should be used as proxy. If not set, proxy is not used.
  -h                Prints this help
`

// main is the main method for ldpreload label injector
// This tool parses block structure of yaml file and currently support only these type of structures:
// 1. basic yaml blocks, i.e.
// ....root:
//....   block1:
//........block2:
// 2.the compact nested mapping, i.e.
//.... mapping:
//.... - item1attribute1:
//....   item1attribute2:
//.... - item2attribute1:
//....   item2attribute2:
func main() {
	// handle initial tasks and simple cases
	flag.Parse() //can't be in init()
	if *help {
		fmt.Print(helpContent)
		return
	}
	injectParams := injectParams{
		useDebugLabel: *useDebugLabel,
		proxyName:     *proxyName,
	}

	// transform input to output
	content, err := readInput()
	if err != nil {
		panic(fmt.Errorf("Can't read input: %v ", err))
	}
	injectedContent, err := inject(string(content), injectParams)
	if err != nil {
		panic(fmt.Errorf("Can't inject ldpreload labels: %v ", err))
	}
	err = writeOutput(injectedContent)
	if err != nil {
		panic(fmt.Errorf("Can't write output: %v ", err))
	}
}

func readInput() (content string, err error) {
	if *inputFile == "" {
		err = fmt.Errorf("Input is not specified, please use -f parameter.\n" + helpContent)
		return
	}
	var contentBytes []byte
	if *inputFile == "-" {
		contentBytes, err = ioutil.ReadAll(os.Stdin)
	} else {
		contentBytes, err = ioutil.ReadFile(*inputFile)
	}
	if err != nil {
		return
	}
	content = string(contentBytes)
	return
}

func writeOutput(content string) error {
	if *outputFile == "" {
		fmt.Print(content)
		return nil
	}
	return ioutil.WriteFile(*outputFile, []byte(content), fileMode(*inputFile))
}

// fileMode computes most appropriate file permissions for output file
func fileMode(input string) os.FileMode {
	fileMode := os.FileMode(0644) //default permissions
	if input == "" || input == "-" {
		return fileMode //input is not file -> can't detect file permissions from input -> using default permissions
	}
	inputFileInfo, err := os.Stat(input)
	if err == nil {
		fileMode = inputFileInfo.Mode()
	} else {
		fmt.Printf("\n  Can't detect file permissions for input file. Using permissions %v for output file. Error: %v \n", fileMode, err)
	}
	return fileMode
}
