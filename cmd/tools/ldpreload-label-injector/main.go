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
	minusIntendCharacter = "-"
	spaceIntendCharacter = " "
	intendCharacters     = minusIntendCharacter + spaceIntendCharacter
	commentCharacters    = "#"
	defaultIntendLength  = 2 //used only when heuristic fails to provide intend lengths used in input file
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
	converted, err := inject(string(content))
	if err != nil {
		return
	}
	err = ioutil.WriteFile(outputFile, []byte(converted), 0644) //TODO fixme: file permissions should be the same of input file (even more important in case when inputFile==outputFile)
	return
}

// inject injects yaml file content with ldpreload labels
func inject(content string) (string, error) {
	eol, err := detectEOLString(content)
	if err != nil {
		return "", err
	}

	var converted bytes.Buffer
	for _, document := range strings.Split(content, "---") {
		if isPod(document) || isDeployment(document) {
			document = insertLDPreloadTrue(document, eol)
			//document = insertAppScope(document, eol)
			converted.WriteString(document)
		} else {
			converted.WriteString(document)
		}
	}
	return converted.String(), nil
}

// insertion is complete information needed for injection of one string into yaml file content string
type insertion struct {
	insertionPoint int
	text           string
}

func insertLDPreloadTrue(document string, eol string) string {
	insertLines := []string{"# ldpreload-related labels", "ldpreload: \"true\""}
	var insertions = &[]insertion{}
	visitInsertionPlaces(newTraversingInfo(document, []string{"spec:", "template:", "metadata:", "labels:"},
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

			//TODO check existence before inserting
			insertions = prepend(insertion{index, buffer.String()}, insertions) // using this order doesn't invalidate indexes of insertions by applying them sequentially
			return
		}, eol))

	//make real insert
	for _, insert := range *insertions {
		document = document[:insert.insertionPoint] + insert.text + document[insert.insertionPoint:]
	}
	return document
}

func insertAppScope(document string, eol string) string {
	visitInsertionPlaces(newTraversingInfo(document, []string{"spec:", "template:", "spec:", "containers:", "-", "env:"},
		func(index int, unresolvedPath []string, resolvedPath []string, block string, parentBlockIntend int) {
			fmt.Println("========================================")
			fmt.Print(block)
			fmt.Println("========================================")
		}, eol))

	return document
}

func prepend(item insertion, slice *[]insertion) *[]insertion {
	newSlice := append([]insertion{item}, *slice...)
	return &newSlice
}

type traversingInfo struct {
	// static info that doesn't change by traversing
	document string
	visitor  func(int, []string, []string, string, int)
	eol      string

	// dynamic info changed by traversing
	unresolvedPath    []string
	resolvedPath      []string
	blockStart        int
	blockEnd          int
	parentBlockIntend int
}

func (t *traversingInfo) newDescending(blockStart int, blockEnd int, parentBlockIntend int) traversingInfo {
	return traversingInfo{
		document: t.document,
		visitor:  t.visitor,
		eol:      t.eol,

		unresolvedPath:    t.unresolvedPath[1:],
		resolvedPath:      append(t.resolvedPath, t.unresolvedPath[0]),
		blockStart:        blockStart,
		blockEnd:          blockEnd,
		parentBlockIntend: parentBlockIntend,
	}
}

func (t *traversingInfo) curBlock() string {
	return t.document[t.blockStart:t.blockEnd]
}

func newTraversingInfo(document string, path []string, visitor func(int, []string, []string, string, int), eol string) traversingInfo {
	return traversingInfo{
		document:          document,
		visitor:           visitor,
		eol:               eol,
		unresolvedPath:    path,
		resolvedPath:      []string{},
		blockStart:        0,
		blockEnd:          len(document),
		parentBlockIntend: 0,
	}
}

func visitInsertionPlaces(i traversingInfo) {
	if len(i.unresolvedPath) == 0 {
		i.visitor(strings.Index(i.curBlock(), i.eol)+len(i.eol)+i.blockStart, i.unresolvedPath, i.resolvedPath, i.curBlock(), i.parentBlockIntend)
		return
	}

	if i.unresolvedPath[0] == "-" { // compact nested mapping
		blockIntend := computeMappingBlockIntend(i.curBlock(), i.eol)
		mappingItemPrefixes := regexp.
			MustCompile(i.eol+"["+strconv.Itoa(blockIntend)+"]+"+minusIntendCharacter).
			FindAllStringIndex(i.curBlock(), -1)
		for _, prefixIndexes := range mappingItemPrefixes {
			//itemBlockStart, itemBlockEnd := computeItemBlockPosition(i.curBlock(), prefixIndexes, blockIntend, i.eol)
			_, _ = computeItemBlockPosition(i.curBlock(), prefixIndexes, blockIntend, i.eol)
		}
	} else { // basic blocks
		blockIntend := computeNormalBlockIntend(i.curBlock(), i.eol)
		matchedBlockPrefixes := regexp.
			MustCompile(i.eol+"["+intendCharacters+"]{"+strconv.Itoa(blockIntend)+"}"+i.unresolvedPath[0]).
			FindAllStringIndex(i.curBlock(), -1)
		if len(matchedBlockPrefixes) == 0 { //next block doesn't exist
			i.visitor(strings.Index(i.curBlock(), i.eol)+len(i.eol)+i.blockStart, i.unresolvedPath, i.resolvedPath, i.curBlock(), i.parentBlockIntend)
			return
		}
		for _, prefixIndexes := range matchedBlockPrefixes {
			childBlockStart, childBlockEnd := computeChildBlockPosition(i.curBlock(), prefixIndexes, blockIntend, i.eol)
			visitInsertionPlaces(i.newDescending(i.blockStart+childBlockStart, i.blockStart+childBlockEnd, blockIntend))
		}
	}
}

func computeNormalBlockIntend(curBlock string, eol string) int {
	return computeBlockIntend(curBlock, eol, "[^"+intendCharacters+commentCharacters+"]{1}")
}

func computeMappingBlockIntend(curBlock string, eol string) int {
	return computeBlockIntend(curBlock, eol, minusIntendCharacter)
}

func computeBlockIntend(curBlock string, eol string, lastCharacterRegExp string) int {
	intendRegExp := eol + "[" + spaceIntendCharacter + "]*" + lastCharacterRegExp //TODO convert intendCharacters to regexp? for "- " is it the same
	intend := regexp.MustCompile(intendRegExp).FindString(curBlock)
	if intend == "" { //block has no child blocks
		return -1
	}
	_, lastRuneSize := utf8.DecodeLastRuneInString(intend)
	return len(intend) - len(eol) - lastRuneSize //TODO convert byte length to rune length? for " " and "-" it is the same length
}

func computeChildBlockPosition(curBlock string, childBlockPrefixIndexes []int, blockIntend int, eol string) (int, int) {
	return computeInnerBlockPosition(curBlock, childBlockPrefixIndexes, blockIntend, eol, "[^"+intendCharacters+commentCharacters+"]{1}")
}

func computeItemBlockPosition(curBlock string, itemBlockPrefixIndexes []int, blockIntend int, eol string) (int, int) {
	return computeInnerBlockPosition(curBlock, itemBlockPrefixIndexes, blockIntend, eol, minusIntendCharacter)
}

func computeInnerBlockPosition(curBlock string, innerBlockPrefixIndexes []int, blockIntend int, eol string, lastCharacterRegExp string) (int, int) {
	start := innerBlockPrefixIndexes[0] + len(eol)                                                                    //without eol from previous block
	nextSibling := eol + "[" + spaceIntendCharacter + "]{" + strconv.Itoa(blockIntend) + "}" + lastCharacterRegExp    //TODO convert intendCharacters to regexp? for "- " is it the same
	nextSiblingIdx := regexp.MustCompile(nextSibling).FindStringIndex(curBlock[innerBlockPrefixIndexes[0]+len(eol):]) // shifted search by len(eol) to not match start of block
	if nextSiblingIdx != nil {
		return start, innerBlockPrefixIndexes[0] + nextSiblingIdx[0] + len(eol) /*shifted sibling search*/ + len(eol) /*include block ending eol (matched by sibling search) */
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
