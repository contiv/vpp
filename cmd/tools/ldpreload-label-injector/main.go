// Package ldpreloadlabelinjector contains tool for injecting ldpreload-specific labels into kubernetes yaml files
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
)

var (
	outputFile    = flag.String("o", "", "Output file override.")
	help          = flag.Bool("h", false, "Switch to show help")
	useDebugLabel = flag.Bool("d", false, "Switch to used debug ldpreload label")
	proxyName     = flag.String("p", "", "Name of proxy container that should be used.")
)

type injectParams struct {
	useDebugLabel bool
	proxyName     string
}

func main() {
	// handle initial tasks and simple cases
	flag.Parse() //can't be in init()
	if *help || flag.NArg() == 0 {
		printHelp()
		return
	}

	// resolve input/output files arguments and start file processing
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

func printHelp() {
	fmt.Print(`ldpreload-label-injector injects ldpreload labels to kubernetes yaml files.
Usage:
  ldpreload-label-injector [input file]

Flags:
  -o [output file]  Sets output for modified kubernetes yaml file. This overrides default behaviour that takes input file as output file and modifies input file in-place.
  -d                Adds ldpreload debug label to yaml kubernetes files
  -h                Prints this help
`)
}

func processFile(inputFile string, outputFile string, params injectParams) (err error) {
	fmt.Printf("Processing file %v (to output %v)", inputFile, outputFile)
	content, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return
	}
	converted, err := inject(string(content), params)
	if err != nil {
		return
	}
	err = ioutil.WriteFile(outputFile, []byte(converted), 0644) //TODO fixme: file permissions should be the same of input file (even more important in case when inputFile==outputFile)
	return
}
