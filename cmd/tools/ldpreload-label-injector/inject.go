package main

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	documentDelimiter         = "---"
	minusIndentationCharacter = "-"
	spaceIndentationCharacter = " "
	indentationCharacters     = minusIndentationCharacter + spaceIndentationCharacter
	commentCharacters         = "#"
	defaultIndentationLength  = 2 //used only when heuristic fails to provide indentation lengths used in input file
)

var (
	deploymentKind = regexp.MustCompile(`kind: *Deployment`)
	podKind        = regexp.MustCompile(`kind: *Pod`)
)

// inject injects yaml file content with ldpreload labels
func inject(content string, params injectParams) (string, error) {
	eol, err := detectEOLString(content)
	if err != nil {
		return "", err
	}

	var converted bytes.Buffer
	for _, document := range strings.Split(content, documentDelimiter) {
		if converted.Len() != 0 {
			converted.WriteString(documentDelimiter)
		}
		if isPod(document) || isDeployment(document) {
			document = insertLDPreloadTrue(document, eol)
			document = insertAppScope(document, eol, params)
			if params.useDebugLabel {
				document = insertDebug(document, eol)
			}
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
	return insertLines(
		document,
		[]string{"spec:", "template:", "metadata:", "labels:"},
		[]string{
			"# ldpreload-related labels",
			"ldpreload: \"true\"",
		},
		eol)
}

func insertAppScope(document string, eol string, params injectParams) string {
	if params.proxyName == "" { // no proxy -> scope is global for all containers
		return insertLines(
			document,
			[]string{"spec:", "template:", "spec:", "containers:", minusIndentationCharacter, "env:"},
			[]string{
				"# ldpreload-related env vars",
				"- name: VCL_APP_SCOPE_GLOBAL",
				"  value: \"\"",
				"- name: VCL_APP_SCOPE_LOCAL",
				"  value: \"\"",
			},
			eol)
	}

	// proxy used
	return insertLinesConditioned(
		document,
		[]string{"spec:", "template:", "spec:", "containers:", minusIndentationCharacter, "env:"},
		isProxyContainer(params.proxyName),
		[]string{ // proxy container settings
			"# ldpreload-related env vars",
			"- name: VCL_APP_SCOPE_GLOBAL",
			"  value: \"\"",
			"- name: VCL_APP_SCOPE_LOCAL",
			"  value: \"\"",
			"- name: VCL_APP_PROXY_TRANSPORT_TCP",
			"  value: \"\"",
		},
		[]string{ // non-proxy container settings
			"# ldpreload-related env vars",
			"- name: VCL_APP_SCOPE_LOCAL",
			"  value: \"\"",
		},
		eol,
	)
}

// isProxyContainer checks if we are inside proxy image or not. This impl is tightly relying on path in insertAppScope() method.
func isProxyContainer(proxyName string) conditionFunc {
	return func(info traversingInfo) bool {
		if len(info.unresolvedPath) > 1 {
			return false // should not happen, because it would mean that there are no containers at all
		}

		imageBlockStr := info.blockStr(len(info.blocks) - (2 - len(info.unresolvedPath)))
		return regexp.MustCompile("name: *"+proxyName+" *"+info.eol).
			FindStringIndex(imageBlockStr) != nil
	}
}

func insertDebug(document string, eol string) string {
	return insertLines(
		document,
		[]string{"spec:", "template:", "spec:", "containers:", minusIndentationCharacter, "env:"},
		[]string{
			"# enable verbose VCL debugs, do not use for production",
			"- name: VCL_DEBUG",
			"  value: \"3\"",
		},
		eol)
}

func insertLines(document string, path []string, insertLines []string, eol string) string {
	return insertLinesConditioned(document, path, func(traversingInfo) bool { return true }, insertLines, []string{}, eol)
}

type conditionFunc func(traversingInfo) bool

func insertLinesConditioned(document string, path []string, condition conditionFunc, insertLines []string, elseInsertLines []string, eol string) string {
	var insertions = &[]insertion{}
	visitInsertionPlaces(newTraversingInfo(document, path,
		func(i traversingInfo) {
			if hasMappingInUresolvedPath(i) {
				return //if there is empty mapping we don't create mapping items just to add labels to it (i.e. we don't create new container to add label to it)
			}
			lines := insertLines
			if !condition(i) {
				lines = elseInsertLines
			}
			insertStr := createIndentationedInsertionString(i, eol, lines)
			insertPoint := strings.Index(i.curBlockStr(), eol) + len(eol) + i.curBlockStart()
			insertions = prepend(insertion{insertPoint, insertStr}, insertions) // using this order doesn't invalidate indexes of insertions by applying them sequentially
			return
		}, eol))

	//make real insert
	for _, insert := range *insertions {
		document = document[:insert.insertionPoint] + insert.text + document[insert.insertionPoint:]
	}
	return document
}

func hasMappingInUresolvedPath(i traversingInfo) bool {
	for _, pathPart := range i.unresolvedPath {
		if pathPart == minusIndentationCharacter {
			return true
		}
	}
	return false
}

func createIndentationedInsertionString(i traversingInfo, eol string, insertLines []string) string {
	//computing indentation delta additions to define inner block indentation
	indentationDelta := defaultIndentationLength // just guess in case we don't have enough information to compute it
	if len(i.resolvedPath) > 1 {
		indentationDelta = round(float64(i.parentBlockIndentation) / float64(len(i.resolvedPath)-1))
	}

	//compute indentation of inner block
	indentation := 0 //default is for case when len(i.resolvedPath) == 0
	if len(i.resolvedPath) > 0 {
		// checking indentation of siblings
		match := regexp.
			MustCompile(i.eol + "([" + spaceIndentationCharacter + "]*?)[^" + spaceIndentationCharacter + commentCharacters + "]{1}").
			FindStringSubmatch(i.curBlockStr())
		if match != nil {
			indentation = len(match[1])
		} else { //no siblings -> using heuristic
			indentation = i.parentBlockIndentation + indentationDelta
		}
	}

	//creating missing path if necessary
	var buffer bytes.Buffer
	if len(i.unresolvedPath) > 0 {
		for _, pathPart := range i.unresolvedPath {
			buffer.WriteString(strings.Repeat(" ", indentation) + pathPart + eol)
			indentation = indentation + indentationDelta
		}
	}

	//creating insertion lines with proper indentation
	for _, line := range insertLines {
		buffer.WriteString(strings.Repeat(" ", indentation) + line + eol)
	}

	return buffer.String()
}

func prepend(item insertion, slice *[]insertion) *[]insertion {
	newSlice := append([]insertion{item}, *slice...)
	return &newSlice
}

type traversingInfo struct {
	// static info that doesn't change by traversing
	document string
	visitor  func(traversingInfo) //passing copy only (slices can still refer back to original array)
	eol      string

	// dynamic info changed by traversing
	unresolvedPath         []string
	resolvedPath           []string
	blocks                 []block
	parentBlockIndentation int
}

type block struct {
	start int
	end   int
}

func newTraversingInfo(document string, path []string, visitor func(traversingInfo), eol string) traversingInfo {
	return traversingInfo{
		document: document,
		visitor:  visitor,
		eol:      eol,

		unresolvedPath:         path,
		resolvedPath:           []string{},
		blocks:                 []block{{0, len(document)}},
		parentBlockIndentation: 0,
	}
}

func (t *traversingInfo) newDescending(blockStart int, blockEnd int, parentBlockIndentation int) traversingInfo {
	return traversingInfo{
		document: t.document,
		visitor:  t.visitor,
		eol:      t.eol,

		unresolvedPath:         t.unresolvedPath[1:],
		resolvedPath:           append(t.resolvedPath, t.unresolvedPath[0]),
		blocks:                 append(t.blocks, block{blockStart, blockEnd}),
		parentBlockIndentation: parentBlockIndentation,
	}
}

func (t *traversingInfo) curBlock() block {
	return t.blocks[len(t.blocks)-1]
}

func (t *traversingInfo) curBlockStart() int {
	return t.curBlock().start
}

func (t *traversingInfo) curBlockEnd() int {
	return t.curBlock().end
}

func (t *traversingInfo) curBlockStr() string {
	return t.document[t.curBlockStart():t.curBlockEnd()]
}

func (t *traversingInfo) blockStr(blockIndex int) string {
	return t.document[t.blocks[blockIndex].start:t.blocks[blockIndex].end]
}

func visitInsertionPlaces(i traversingInfo) {
	if len(i.unresolvedPath) == 0 {
		i.visitor(i)
		return
	}

	if i.unresolvedPath[0] == minusIndentationCharacter { // compact nested mapping
		blockIndentation := computeMappingBlockIndentation(i.curBlockStr(), i.eol)
		mappingItemPrefixes := regexp.
			MustCompile(i.eol+"["+spaceIndentationCharacter+"]{"+strconv.Itoa(blockIndentation)+"}"+minusIndentationCharacter).
			FindAllStringIndex(i.curBlockStr(), -1)
		for _, prefixIndexes := range mappingItemPrefixes {
			itemBlockStart, itemBlockEnd := computeItemBlockPosition(i.curBlockStr(), prefixIndexes, blockIndentation, i.eol)

			// recursive call would not handle map item block correctly => handling 1 recursive call here (recursive calls
			// can continue when in mapping items are normal blocks again)
			// Expecting that unresolved paths can't end with minusIndentationCharacter
			childBlockIndentation := computeItemBlockIndentation(i.curBlockStr(), i.eol)
			handleBasicBlock(i.newDescending(i.curBlockStart()+itemBlockStart, i.curBlockStart()+itemBlockEnd, blockIndentation), childBlockIndentation)
		}
	} else { // basic blocks
		blockIndentation := computeNormalBlockIndentation(i.curBlockStr(), i.eol)
		handleBasicBlock(i, blockIndentation)
	}
}

func handleBasicBlock(i traversingInfo, blockIndentation int) {
	matchedBlockPrefixes := regexp.
		MustCompile(i.eol+"["+indentationCharacters+"]{"+strconv.Itoa(blockIndentation)+"}"+i.unresolvedPath[0]).
		FindAllStringIndex(i.curBlockStr(), -1)
	if len(matchedBlockPrefixes) == 0 { //next block doesn't exist
		i.visitor(i)
		return
	}
	for _, prefixIndexes := range matchedBlockPrefixes {
		childBlockStart, childBlockEnd := computeChildBlockPosition(i.curBlockStr(), prefixIndexes, blockIndentation, i.eol)
		visitInsertionPlaces(i.newDescending(i.curBlockStart()+childBlockStart, i.curBlockStart()+childBlockEnd, blockIndentation))
	}
}

func computeNormalBlockIndentation(curBlock string, eol string) int {
	return computeBlockIndentation(curBlock, eol, eol+"["+spaceIndentationCharacter+"]*[^"+indentationCharacters+commentCharacters+"]{1}")
}

func computeMappingBlockIndentation(curBlock string, eol string) int {
	return computeBlockIndentation(curBlock, eol, eol+"["+spaceIndentationCharacter+"]*"+minusIndentationCharacter)
}

func computeItemBlockIndentation(curBlock string, eol string) int {
	return computeBlockIndentation(curBlock, eol, eol+"["+indentationCharacters+"]*[^"+indentationCharacters+commentCharacters+"]{1}")
}

func computeBlockIndentation(curBlock string, eol string, indentationRegExp string) int {
	indentation := regexp.MustCompile(indentationRegExp).FindString(curBlock)
	if indentation == "" { //block has no child blocks
		return -1
	}
	_, lastRuneSize := utf8.DecodeLastRuneInString(indentation)
	return len(indentation) - len(eol) - lastRuneSize
}

func computeChildBlockPosition(curBlock string, childBlockPrefixIndexes []int, blockIndentation int, eol string) (int, int) {
	return computeInnerBlockPosition(curBlock, childBlockPrefixIndexes, blockIndentation, eol, "[^"+indentationCharacters+commentCharacters+"]{1}")
}

func computeItemBlockPosition(curBlock string, itemBlockPrefixIndexes []int, blockIndentation int, eol string) (int, int) {
	return computeInnerBlockPosition(curBlock, itemBlockPrefixIndexes, blockIndentation, eol, minusIndentationCharacter)
}

func computeInnerBlockPosition(curBlock string, innerBlockPrefixIndexes []int, blockIndentation int, eol string, lastCharacterRegExp string) (int, int) {
	start := innerBlockPrefixIndexes[0] + len(eol) //without eol from previous block
	nextSibling := eol + "[" + spaceIndentationCharacter + "]{" + strconv.Itoa(blockIndentation) + "}" + lastCharacterRegExp
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

func round(f float64) int {
	if f < -0.5 {
		return int(f - 0.5)
	}
	if f > 0.5 {
		return int(f + 0.5)
	}
	return 0
}
