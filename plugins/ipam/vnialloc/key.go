package vnialloc

import (
	"strconv"
	"strings"
)

// Keyword defines the keyword identifying custom vni allocation data for SFC vxlan.
const Keyword = "custom-vni-sfc"

// KeyPrefix return prefix where all vni service function chain configs are persisted.
func KeyPrefix() string {
	return Keyword + "/"
}

// Key returns the key under which custom vni of an SFC instance should be stored in the data-store.
func Key(sfcName string, sfcInstance uint32) string {
	return KeyPrefix() + sfcName + "/" + strconv.FormatUint(uint64(sfcInstance), 10)
}

// ParseKey parses SFC name and SFC instance number from key identifying custom VNI allocation data for SFC_vxlan.
// Returns empty strings if parsing fails (invalid key).
func ParseKey(key string) (sfcName string, sfcInstance uint32) {
	if strings.HasPrefix(key, KeyPrefix()) {
		parts := strings.Split(strings.TrimPrefix(key, KeyPrefix()), "/")
		if len(parts) == 2 {
			sfcInst, err := strconv.Atoi(parts[1])
			if err == nil {
				return parts[0], uint32(sfcInst)
			}
		}
	}
	return
}
