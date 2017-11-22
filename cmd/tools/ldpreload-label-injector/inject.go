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
	minusIntendCharacter = "-"
	spaceIntendCharacter = " "
	intendCharacters     = minusIntendCharacter + spaceIntendCharacter
	commentCharacters    = "#"
	defaultIntendLength  = 2 //used only when heuristic fails to provide intend lengths used in input file
)

var (
	deploymentKind = regexp.MustCompile(`kind: *Deployment`)
	podKind        = regexp.MustCompile(`kind: *Pod`)
)

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
			document = insertAppScope(document, eol)
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

func insertAppScope(document string, eol string) string {
	return insertLines(
		document,
		[]string{"spec:", "template:", "spec:", "containers:", "-", "env:"},
		[]string{
			"# ldpreload-related env vars",
			"- name: VCL_APP_SCOPE_GLOBAL",
			"  value: \"\"",
		},
		eol)
}

func insertLines(document string, path []string, insertLines []string, eol string) string {
	var insertions = &[]insertion{}
	visitInsertionPlaces(newTraversingInfo(document, path,
		func(index int, unresolvedPath []string, resolvedPath []string, block string, parentBlockIntend int) {
			intendDelta := defaultIntendLength // just guess in case we don't have enough information to compute it
			if len(resolvedPath) > 1 {
				intendDelta = round(float64(parentBlockIntend) / float64(len(resolvedPath)-1))
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
			MustCompile(i.eol+"["+spaceIntendCharacter+"]{"+strconv.Itoa(blockIntend)+"}"+minusIntendCharacter).
			FindAllStringIndex(i.curBlock(), -1)
		for _, prefixIndexes := range mappingItemPrefixes {
			itemBlockStart, itemBlockEnd := computeItemBlockPosition(i.curBlock(), prefixIndexes, blockIntend, i.eol)

			// recursive call would not handle map item block correctly => handling 1 recursive call here (recursive calls
			// can continue when in mapping items are normal blocks again)
			// Expecting that unresolved paths can't end with "-"
			childBlockIntend := computeItemBlockIntend(i.curBlock(), i.eol)
			handleBasicBlock(i.newDescending(i.blockStart+itemBlockStart, i.blockStart+itemBlockEnd, childBlockIntend), childBlockIntend)
		}
	} else { // basic blocks
		blockIntend := computeNormalBlockIntend(i.curBlock(), i.eol)
		handleBasicBlock(i, blockIntend)
	}
}

func handleBasicBlock(i traversingInfo, blockIntend int) {
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

func computeNormalBlockIntend(curBlock string, eol string) int {
	return computeBlockIntend(curBlock, eol, eol+"["+spaceIntendCharacter+"]*[^"+intendCharacters+commentCharacters+"]{1}") //TODO convert intendCharacters to regexp? for "- " is it the same
}

func computeMappingBlockIntend(curBlock string, eol string) int {
	return computeBlockIntend(curBlock, eol, eol+"["+spaceIntendCharacter+"]*"+minusIntendCharacter) //TODO convert intendCharacters to regexp? for "- " is it the same
}

func computeItemBlockIntend(curBlock string, eol string) int {
	return computeBlockIntend(curBlock, eol, eol+"["+intendCharacters+"]*[^"+intendCharacters+commentCharacters+"]{1}") //TODO convert intendCharacters to regexp? for "- " is it the same
}

func computeBlockIntend(curBlock string, eol string, intendRegExp string) int {
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

func round(f float64) int {
	if f < -0.5 {
		return int(f - 0.5)
	}
	if f > 0.5 {
		return int(f + 0.5)
	}
	return 0
}
