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
	// static regular expressions
	deploymentKind = regexp.MustCompile(`kind: *Deployment`)
	podKind        = regexp.MustCompile(`kind: *Pod`)
)

// inject injects yaml file content with ldpreload labels
func inject(content string, params injectParams) (string, error) {
	// detect end of line character used in content
	eol, err := detectEOLString(content)
	if err != nil {
		return "", err
	}

	// split yaml to documents and apply series of labels to each one
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

// insertLDPreloadTrue inserts label that enables ldpreload
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

// insertAppScope inserts application scope ldpreload labels
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

// insertDebug inserts ldpreload label that enables ldpreload debugging
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

// insertLines inserts <insertLines> to yaml <document> at position defined by <path>.
// Yaml document is a block structured document. <path> is used to navigate from root block of document to the most
// inner block where the lines should be inserted.
func insertLines(document string, path []string, insertLines []string, eol string) string {
	return insertLinesConditioned(document, path, func(traversingInfo) bool { return true }, insertLines, []string{}, eol)
}

type conditionFunc func(traversingInfo) bool

// insertLinesConditioned is extended version of insertLines function and it can choose between 2 possible texts to insert based on condition (conditionFunc)
func insertLinesConditioned(document string, path []string, condition conditionFunc, insertLines []string, elseInsertLines []string, eol string) string {
	// visit places where text need to be inserted and by using information information collected by travelling (traversing info)
	// build insertion information (where and what should be inserted)
	// When text for insertion is constructed, it is not inserted right away because that would invalidate some
	// indexes (navigation in document is index based, block are remembered as <startindex, endindex>)
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

	//use collected insertion informations and make real insert
	for _, insert := range *insertions {
		document = document[:insert.insertionPoint] + insert.text + document[insert.insertionPoint:]
	}
	return document
}

// hasMappingInUresolvedPath checks whether unresolved path has mapping
func hasMappingInUresolvedPath(i traversingInfo) bool {
	for _, pathPart := range i.unresolvedPath {
		if pathPart == minusIndentationCharacter {
			return true
		}
	}
	return false
}

// createIndentationedInsertionString adds correct indentation for <insertLines> based on block where it should be inserted.
// It also handles situations when we don't end in destination block, because it doesn't exist. In such cases this function
// should be called in the last existing block and this function will create text representation for rest of missing blocks
// and insert them before text that we want to insert.
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

// traversingInfo is container for data needed to follow block-defined path in yaml block-oriented document and to
// fullfill information needs of visitor functions (see visitInsertionPlaces function).
// Each traversed block has new traversingInfo. Some of the information just passed (static info) and some recomputed (dynamic infor)
type traversingInfo struct {
	// static info that doesn't change by traversing
	document string               //whole document
	visitor  func(traversingInfo) //function called when we get to destination block (or to last existing block on path  to destination block ), passing copy only (slices can still refer back to original array)
	eol      string               // end of line character detected from document

	// dynamic info changed by traversing
	unresolvedPath         []string //part of path that lies ahead of us
	resolvedPath           []string //part of path that we already walked
	blocks                 []block  //blocks from path-walking that we already visited (in order of visiting)
	parentBlockIndentation int      //indentation length of last visited block
}

// block is definition of document part representing "block". After identifying block in document, this data container is used to remember it.
type block struct {
	start int
	end   int
}

// newTraversingInfo creates initial traversing info that is meant for root block of document
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

// newDescending creates new travesing info that should correspond to child block as this traversing info corresponded to parent block
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

// curBlock is helper function to get current block
func (t *traversingInfo) curBlock() block {
	return t.blocks[len(t.blocks)-1]
}

// curBlockStart is helper function to get start of current block
func (t *traversingInfo) curBlockStart() int {
	return t.curBlock().start
}

// curBlockEnd is helper function to get end of current block
func (t *traversingInfo) curBlockEnd() int {
	return t.curBlock().end
}

// curBlockStr is helper function to get document's string content for current block
func (t *traversingInfo) curBlockStr() string {
	return t.document[t.curBlockStart():t.curBlockEnd()]
}

// blockStr is helper function to get document's string content for <blockIndex>-th visited block
func (t *traversingInfo) blockStr(blockIndex int) string {
	return t.document[t.blocks[blockIndex].start:t.blocks[blockIndex].end]
}

// visitInsertionPlaces traverse block-based document(<i.document>) by following block-based path(<i.path>) and in the
// destination block visitor function (<i.visitor>) is called. Visitor function should not change document by inserting
// text into it, but merely use information provided to it to handle later the insertion of text itself.
// For supported yaml structures see documentation of main method of ldpreload inject tool.
func visitInsertionPlaces(i traversingInfo) {
	if len(i.unresolvedPath) == 0 {
		i.visitor(i)
		return
	}

	if i.unresolvedPath[0] == minusIndentationCharacter { // compact nested mapping
		mappingItemIndentation := computeChildIndentationForMappingBlock(i.curBlockStr(), i.eol)
		mappingItemPrefixes := regexp.
			MustCompile(i.eol+"["+spaceIndentationCharacter+"]{"+strconv.Itoa(mappingItemIndentation)+"}"+minusIndentationCharacter).
			FindAllStringIndex(i.curBlockStr(), -1)
		for _, prefixIndexes := range mappingItemPrefixes {
			itemBlock := computeItemBlockPosition(i.curBlockStr(), prefixIndexes, mappingItemIndentation, i.eol)

			// recursive call would not handle map item block correctly => handling 1 recursive call here (recursive calls
			// can continue when in mapping items are normal blocks again)
			// Expecting that unresolved paths can't end with minusIndentationCharacter
			itemChildBlockIndentation := computeChildIndentationForItemBlock(i.curBlockStr(), i.eol)
			handleBasicBlock(i.newDescending(i.curBlockStart()+itemBlock.start, i.curBlockStart()+itemBlock.end, mappingItemIndentation), itemChildBlockIndentation)
		}
	} else { // basic blocks
		blockIndentation := computeChildIndentationForNormalBlock(i.curBlockStr(), i.eol)
		handleBasicBlock(i, blockIndentation)
	}
}

// handleBasicBlock detects child of basic block and continues traversing on it(call to visitInsertionPlaces function)
func handleBasicBlock(i traversingInfo, blockIndentation int) {
	matchedBlockPrefixes := regexp.
		MustCompile(i.eol+"["+indentationCharacters+"]{"+strconv.Itoa(blockIndentation)+"}"+i.unresolvedPath[0]).
		FindAllStringIndex(i.curBlockStr(), -1)
	if len(matchedBlockPrefixes) == 0 { //next block doesn't exist
		i.visitor(i)
		return
	}
	for _, prefixIndexes := range matchedBlockPrefixes {
		childBlock := computeChildBlockPosition(i.curBlockStr(), prefixIndexes, blockIndentation, i.eol)
		visitInsertionPlaces(i.newDescending(i.curBlockStart()+childBlock.start, i.curBlockStart()+childBlock.end, blockIndentation))
	}
}

func computeChildIndentationForNormalBlock(normalBlock string, eol string) int {
	return computeChildIndentation(normalBlock, eol, eol+"["+spaceIndentationCharacter+"]*[^"+indentationCharacters+commentCharacters+"]{1}")
}

func computeChildIndentationForMappingBlock(mappingBlock string, eol string) int {
	return computeChildIndentation(mappingBlock, eol, eol+"["+spaceIndentationCharacter+"]*"+minusIndentationCharacter)
}

func computeChildIndentationForItemBlock(itemBlock string, eol string) int {
	return computeChildIndentation(itemBlock, eol, eol+"["+indentationCharacters+"]*[^"+indentationCharacters+commentCharacters+"]{1}")
}

// computeChildIndentation computes child block indentation for current block when child block indentation matcher regular expression is given
func computeChildIndentation(curBlock string, eol string, indentationRegExp string) int {
	indentation := regexp.MustCompile(indentationRegExp).FindString(curBlock)
	if indentation == "" { //block has no child blocks
		return -1
	}
	_, lastRuneSize := utf8.DecodeLastRuneInString(indentation)
	return len(indentation) - len(eol) - lastRuneSize
}

func computeChildBlockPosition(curBlock string, childBlockPrefixIndexes []int, blockIndentation int, eol string) block {
	return computeInnerBlockPosition(curBlock, childBlockPrefixIndexes, blockIndentation, eol, "[^"+indentationCharacters+commentCharacters+"]{1}")
}

func computeItemBlockPosition(curBlock string, itemBlockPrefixIndexes []int, blockIndentation int, eol string) block {
	return computeInnerBlockPosition(curBlock, itemBlockPrefixIndexes, blockIndentation, eol, minusIndentationCharacter)
}

// computeInnerBlockPosition computes inner block boundaries
func computeInnerBlockPosition(curBlock string, innerBlockPrefixIndexes []int, blockIndentation int, eol string, lastCharacterRegExp string) block {
	start := innerBlockPrefixIndexes[0] + len(eol) //without eol from previous block
	nextSibling := eol + "[" + spaceIndentationCharacter + "]{" + strconv.Itoa(blockIndentation) + "}" + lastCharacterRegExp
	nextSiblingIdx := regexp.MustCompile(nextSibling).FindStringIndex(curBlock[innerBlockPrefixIndexes[0]+len(eol):]) // shifted search by len(eol) to not match start of block
	if nextSiblingIdx != nil {
		return block{start, innerBlockPrefixIndexes[0] + nextSiblingIdx[0] + len(eol) /*shifted sibling search*/ + len(eol) /*include block ending eol (matched by sibling search) */}
	}
	return block{start, len(curBlock)}
}

// detectEOLString is helper method to get end-of-line character from file content.
// This is preferred way of getting end-of-line character as opposed to force to use hardcoded character.
func detectEOLString(content string) (string, error) {
	for _, eol := range []string{"\r\n", "\n", "\r"} {
		if strings.Contains(content, eol) {
			return eol, nil
		}
	}
	return "", fmt.Errorf("can't detect end of line characters")
}

// isDeployment detects whether document has kind set to deployment
func isDeployment(document string) bool {
	return len(deploymentKind.FindString(document)) != 0
}

// isPod detects whether document has kind set to pod
func isPod(document string) bool {
	return len(podKind.FindString(document)) != 0
}

// round is helper function because golang can't round numbers
func round(f float64) int {
	if f < -0.5 {
		return int(f - 0.5)
	}
	if f > 0.5 {
		return int(f + 0.5)
	}
	return 0
}

// prepend is helper function for creating insertion slice in reverted order as we got items for the slice
func prepend(item insertion, slice *[]insertion) *[]insertion {
	newSlice := append([]insertion{item}, *slice...)
	return &newSlice
}
