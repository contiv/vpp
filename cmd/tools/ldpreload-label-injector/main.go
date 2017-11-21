// Package ldpreloadlabelinjector contains tool for injecting ldpreload-specific labels into kubernetes yaml files
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	intendCharacters    = "- "
	commentCharacters   = "#"
	defaultIntendLength = 2 //used only when heuristic fails to provide intend lengths used in input file
)

var (
	outputFile     = flag.String("o", "", "Output file override.")
	help           = flag.Bool("h", false, "Switch to show help")
	deploymentKind = regexp.MustCompile(`kind: *Deployment`)
	podKind        = regexp.MustCompile(`kind: *Pod`)
)

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
	if err := processFile(inputFile, *outputFile); err != nil {
		panic(fmt.Errorf("Can't process file %v : %v ", inputFile, err))
	}
}

func printHelp() {
	fmt.Print(`ldpreload-label-injector injects ldpreload labels to kubernetes yaml files.
Usage:
  ldpreload-label-injector [input file]

Flags:
  -o [output file]  Sets output for modified kubernetes yaml file. This overrides default behaviour that takes input file as output file and modifies input file in-place.
  -h                Prints this help
`)
}

func processFile(inputFile string, outputFile string) (err error) {
	fmt.Printf("Processing file %v (to output %v)", inputFile, outputFile)
	content, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return
	}
	converted, err := ConvertFileContent(string(content))
	if err != nil {
		return
	}
	err = ioutil.WriteFile(outputFile, []byte(converted), 0644) //TODO fixme: file permissions should be the same of input file (even more important in case when inputFile==outputFile)
	return
}

func ConvertFileContent(content string) (string, error) {
	eol, err := detectEOLString(content)
	if err != nil {
		return "", err
	}

	var converted bytes.Buffer
	for _, document := range strings.Split(content, "---") {
		if isPod(document) || isDeployment(document) {
			converted.WriteString(insertLDPreloadTrue(document, eol))
		} else {
			converted.WriteString(document)
		}
	}
	return converted.String(), nil
}

type Insertion struct {
	insertionPoint int
	text           string
}

func insertLDPreloadTrue(document string, eol string) string {
	insertLines := []string{"# ldpreload-related labels", "ldpreload: \"true\""}
	var insertions = &[]Insertion{}
	visitInsertionPlaces(document, []string{"spec:", "template:", "metadata:", "labels:"}, []string{},
		func(index int, unresolvedPath []string, resolvedPath []string, block string, parentBlockIntend int) {
			intendDelta := defaultIntendLength // just guess in case we don't have enough information to compute it
			if len(resolvedPath) > 1 {
				intendDelta = parentBlockIntend / (len(resolvedPath) - 1)
			}

			var buffer bytes.Buffer
			if len(unresolvedPath) > 0 {
				if len(resolvedPath) == 0 {
					parentBlockIntend = -intendDelta // if there is no top level block then we must start with no intend
				}
				for _, pathPart := range unresolvedPath {
					buffer.WriteString(strings.Repeat(" ", parentBlockIntend+intendDelta) + pathPart + eol)
					parentBlockIntend = parentBlockIntend + intendDelta
				}
			}
			for _, line := range insertLines {
				buffer.WriteString(strings.Repeat(" ", parentBlockIntend+intendDelta) + line + eol)
			}

			insertions = prepend(Insertion{index, buffer.String()}, insertions) // using this order doesn't invalidate indexes of insertions by applying them sequentially
			return
		},
		0, len(document), eol, 0, 0)

	//make real insert
	for _, insert := range *insertions {
		document = document[:insert.insertionPoint] + insert.text + document[insert.insertionPoint:]
	}
	return document
}

func prepend(item Insertion, slice *[]Insertion) *[]Insertion {
	newSlice := append([]Insertion{item}, *slice...)
	return &newSlice
}

func visitInsertionPlaces(doc string, unresolvedPath []string, resolvedPath []string, visitor func(int, []string, []string, string, int), blockStart int, blockEnd int, eol string, parentBlockIntend int, blockIntend int) {
	curBlock := doc[blockStart:blockEnd]
	if len(unresolvedPath) == 0 {
		visitor(strings.Index(curBlock, eol)+len(eol)+blockStart, unresolvedPath, resolvedPath, curBlock, parentBlockIntend)
		return
	}
	matchedBlockPrefixes := regexp.
		MustCompile(eol+"["+intendCharacters+"]{"+strconv.Itoa(blockIntend)+"}"+unresolvedPath[0]).
		FindAllStringIndex(curBlock, -1)
	if len(matchedBlockPrefixes) == 0 { //next block doesn't exist
		visitor(strings.Index(curBlock, eol)+len(eol)+blockStart, unresolvedPath, resolvedPath, curBlock, parentBlockIntend)
		return
	}
	for _, prefixIndexes := range matchedBlockPrefixes {
		childBlockStart, childBlockEnd := computeChildBlockPosition(curBlock, prefixIndexes, blockIntend, eol)
		childBlockIntend := computeChildBlockIntend(curBlock, childBlockStart, childBlockEnd, eol)
		visitInsertionPlaces(doc, unresolvedPath[1:], append(resolvedPath, unresolvedPath[0]), visitor, blockStart+childBlockStart, blockStart+childBlockEnd, eol, blockIntend, childBlockIntend)
	}
}
func computeChildBlockIntend(curBlock string, childBlockStart int, childBlockEnd int, eol string) int {
	nextChildIntendRegExp := eol + "[" + intendCharacters + "]+[^" + intendCharacters + commentCharacters + "]{1}" //TODO convert intendCharacters to regexp? for "- " is it the same
	nextChildIntend := regexp.MustCompile(nextChildIntendRegExp).FindString(curBlock[childBlockStart:childBlockEnd])
	if nextChildIntend == "" { //block has no child blocks
		return -1
	}
	_, lastRuneSize := utf8.DecodeLastRuneInString(nextChildIntend)
	return len(nextChildIntend) - len(eol) - lastRuneSize //TODO convert byte length to rune length? for " " and "-" it is the same length
}
func computeChildBlockPosition(curBlock string, childBlockPrefixIndexes []int, blockIntend int, eol string) (int, int) {
	start := childBlockPrefixIndexes[0] + len(eol)                                                                                         //without eol from previous block
	nextSibling := eol + "[" + intendCharacters + "]{" + strconv.Itoa(blockIntend) + "}[^" + intendCharacters + commentCharacters + "]{1}" //TODO convert intendCharacters to regexp? for "- " is it the same
	nextSiblingIdx := regexp.MustCompile(nextSibling).FindStringIndex(curBlock[childBlockPrefixIndexes[0]+len(eol):])                      // shifted search by len(eol) to not match start of block
	if nextSiblingIdx != nil {
		return start, childBlockPrefixIndexes[0] + nextSiblingIdx[0] + len(eol) /*shifted sibling search*/ + len(eol) /*include block ending eol (matched by sibling search) */
	}
	return start, len(curBlock)
}

func detectEOLString(content string) (string, error) {
	for _, eol := range []string{"\r\n", "\n", "\r"} {
		if strings.Contains(content, eol) {
			return eol, nil
		}
	}
	return "", fmt.Errorf("can't detect end of line characters")
}

func isDeployment(document string) bool {
	return len(deploymentKind.FindString(document)) != 0
}

func isPod(document string) bool {
	return len(podKind.FindString(document)) != 0
}
