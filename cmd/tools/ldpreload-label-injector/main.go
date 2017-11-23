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
	outputFile    = flag.String("o", "", "Output file override.")
	help          = flag.Bool("h", false, "Switch to show help")
	useDebugLabel = flag.Bool("d", false, "Switch to used debug ldpreload label")
	proxyName     = flag.String("p", "", "Name of proxy container that should be used.")
)

// injectParams pass important information from command line flags to injector
type injectParams struct {
	useDebugLabel bool
	proxyName     string
}

// main is the main method for ldpreload label injector
func main() {
	// handle initial tasks and simple cases
	flag.Parse() //can't be in init()
	if *help || flag.NArg() == 0 {
		printHelp()
		return
	}

	// resolve input/output files arguments, info passing to injector and start file processing
	inputFile := flag.Arg(0)
	if len(*outputFile) == 0 {
		outputFile = &inputFile
	}
	injectParams := injectParams{
		useDebugLabel: *useDebugLabel,
		proxyName:     *proxyName,
	}
	if err := processFile(inputFile, *outputFile, injectParams); err != nil {
		panic(fmt.Errorf("Can't process file %v : %v ", inputFile, err))
	}
}

// printHelp prints properly structured help for command line environment
func printHelp() {
	fmt.Print(`ldpreload-label-injector injects ldpreload labels to kubernetes yaml files.
Usage:
  ldpreload-label-injector [input file]

Flags:
  -o [output file]  Sets output for modified kubernetes yaml file. This overrides default behaviour that takes input file as output file and modifies input file in-place.
  -d                Adds ldpreload debug label to yaml kubernetes files
  -p                Sets the name of container that should be used as proxy. If not set, proxy is not used.
  -h                Prints this help
`)
}

// processFile takes content of input file, injects that the ldpreload labels and outputs it as output file
func processFile(inputFile string, outputFile string, params injectParams) (err error) {
	fmt.Printf("Processing file %v (to output %v)... ", inputFile, outputFile)
	content, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return
	}
	converted, err := inject(string(content), params)
	if err != nil {
		return
	}

	err = ioutil.WriteFile(outputFile, []byte(converted), fileMode(inputFile))
	fmt.Println("Done")
	return
}

// fileMode computes most appropriate file permissions for output file
func fileMode(inputFile string) os.FileMode {
	fileMode := os.FileMode(0644) //default permissions
	inputFileInfo, err := os.Stat(inputFile)
	if err == nil {
		fileMode = inputFileInfo.Mode()
	} else {
		fmt.Printf("\n  Can't detect file permissions for input file. Using permissions %v for output file. Error: %v \n", fileMode, err)
	}
	return fileMode
}
