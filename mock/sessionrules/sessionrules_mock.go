package sessionrules

import (
	"bytes"
	"net"
	"strings"

	govppmock "git.fd.io/govpp.git/adapter/mock"
	govppapi "git.fd.io/govpp.git/api"
	govpp "git.fd.io/govpp.git/core"
	"git.fd.io/govpp.git/core/bin_api/vpe"

	"github.com/ligato/cn-infra/logging"

	"github.com/contiv/vpp/plugins/policy/renderer/vpptcp/bin_api/session"
	"github.com/contiv/vpp/plugins/policy/renderer/vpptcp/cache"
)

// MockSessionRules simulates session rules from VPPTCP stack.
// The installed rules are only stored locally and can be queried for testing
// purposes.
type MockSessionRules struct {
	Log       logging.Logger
	tagPrefix string

	vppMock     *govppmock.VppAdapter
	vppConn     *govpp.Connection
	localTable  map[uint32]SessionRules // namespace index -> rules
	globalTable SessionRules
	tags        map[string]struct{}
	errCount    int
	reqCount    int
}

// LocalTableCheck allows to check the content of a local table.
type LocalTableCheck struct {
	nsIndex uint32
	session *MockSessionRules
}

// LocalTableCheck allows to check the content of the global table.
type GlobalTableCheck struct {
	session *MockSessionRules
}

// SessionRules is a list of session rules.
type SessionRules []*cache.SessionRule

// NewMockSessionRules is a constructor for MockSessionRules.
// Create only one in the entire test suite.
// Clear state between tests using the Clear() method.
func NewMockSessionRules(log logging.Logger, tagPrefix string) *MockSessionRules {
	var err error
	mock := &MockSessionRules{
		Log:         log,
		tagPrefix:   tagPrefix,
		vppMock:     &govppmock.VppAdapter{},
		localTable:  make(map[uint32]SessionRules),
		globalTable: SessionRules{},
		tags:        make(map[string]struct{}),
	}
	mock.vppMock.RegisterBinAPITypes(session.Types)
	mock.vppMock.MockReplyHandler(mock.msgReplyHandler)
	mock.vppMock.GetMsgID("session_rules_dump", "")
	mock.vppMock.GetMsgID("session_rules_details", "")
	mock.vppMock.GetMsgID("session_rule_add_del", "")
	mock.vppMock.GetMsgID("session_rule_add_del_reply", "")
	mock.vppConn, err = govpp.Connect(mock.vppMock)
	if err != nil {
		return nil
	}
	return mock
}

// Clear clears the state of the mocked session.
func (msr *MockSessionRules) Clear() {
	msr.localTable = make(map[uint32]SessionRules)
	msr.globalTable = SessionRules{}
	msr.tags = make(map[string]struct{})
	msr.errCount = 0
	msr.reqCount = 0
}

// NewVPPChan creates a new mock VPP channel.
func (msr *MockSessionRules) NewVPPChan() *govppapi.Channel {
	channel, _ := msr.vppConn.NewAPIChannel()
	return channel
}

// GetErrCount returns the number of errors that have occured so far.
func (msr *MockSessionRules) GetErrCount() int {
	return msr.errCount
}

// GetReqCount returns the number of requests that have been received so far.
func (msr *MockSessionRules) GetReqCount() int {
	return msr.reqCount
}

// LocalTable allows to access checks for a local table.
func (msr *MockSessionRules) LocalTable(nsIndex uint32) *LocalTableCheck {
	return &LocalTableCheck{nsIndex: nsIndex, session: msr}
}

// GlobalTable allows to access checks for the global table.
func (msr *MockSessionRules) GlobalTable() *GlobalTableCheck {
	return &GlobalTableCheck{session: msr}
}

// NumOfRules returns the number of rules in the table.
func (ltc *LocalTableCheck) NumOfRules() int {
	table, exists := ltc.session.localTable[ltc.nsIndex]
	if !exists {
		return 0
	}
	return len(table)
}

// NumOfRules returns the number of rules in the table.
func (gtc *GlobalTableCheck) NumOfRules() int {
	return len(gtc.session.globalTable)
}

// HasRule returns <true> if the given rule is present in the table.
func (ltc *LocalTableCheck) HasRule(lclIP string, lclPort uint16, rmtIP string, rmtPort uint16, proto string, action string) bool {
	table, exists := ltc.session.localTable[ltc.nsIndex]
	if !exists {
		return false
	}
	return ltc.session.hasRule(table, cache.RuleScopeLocal, ltc.nsIndex, lclIP, lclPort, rmtIP, rmtPort, proto, action)
}

// HasRule returns <true> if the given rule is present in the table.
func (gtc *GlobalTableCheck) HasRule(lclIP string, lclPort uint16, rmtIP string, rmtPort uint16, proto string, action string) bool {
	return gtc.session.hasRule(gtc.session.globalTable, cache.RuleScopeGlobal, 0, lclIP, lclPort, rmtIP, rmtPort, proto, action)
}

// hasRule returns <true> if the given rule is present in the given table.
func (msr *MockSessionRules) hasRule(table SessionRules, scope uint8, nsIndex uint32,
	lclIP string, lclPort uint16, rmtIP string, rmtPort uint16, proto string, action string) bool {

	var err error

	// Construct SessionRule.
	rule := cache.SessionRule{
		LclPort:    lclPort,
		RmtPort:    rmtPort,
		AppnsIndex: nsIndex,
		Scope:      scope,
	}

	// Parse transport protocol.
	var transportProto uint8
	switch proto {
	case "TCP":
		transportProto = cache.RuleProtoTCP
	case "UDP":
		transportProto = cache.RuleProtoUDP
	}
	rule.TransportProto = transportProto

	// Parse action.
	var actionIndex uint32
	switch action {
	case "ALLOW":
		actionIndex = cache.RuleActionAllow
	case "DENY":
		actionIndex = cache.RuleActionDeny
	}
	rule.ActionIndex = actionIndex

	// Parse IP addresses.
	isIPv4 := uint8(0)
	if lclIP != "" {
		var lclIPNet *net.IPNet
		if !strings.Contains(lclIP, "/") {
			lclIPNet = getOneHostSubnet(lclIP)
		} else {
			_, lclIPNet, err = net.ParseCIDR(lclIP)
			if err != nil {
				return false
			}
		}
		if lclIPNet.IP.To4() != nil {
			isIPv4 = 1
			copy(rule.LclIP[:], lclIPNet.IP.To4())
		} else {
			copy(rule.LclIP[:], lclIPNet.IP.To16())
		}
		lclPlen, _ := lclIPNet.Mask.Size()
		rule.LclPlen = uint8(lclPlen)
	}
	if rmtIP != "" {
		var rmtIPNet *net.IPNet
		if !strings.Contains(rmtIP, "/") {
			rmtIPNet = getOneHostSubnet(rmtIP)
		} else {
			_, rmtIPNet, err = net.ParseCIDR(rmtIP)
			if err != nil {
				return false
			}
		}
		if rmtIPNet.IP.To4() != nil {
			isIPv4 = 1
			copy(rule.RmtIP[:], rmtIPNet.IP.To4())
		} else {
			copy(rule.RmtIP[:], rmtIPNet.IP.To16())
		}
		rmtPlen, _ := rmtIPNet.Mask.Size()
		rule.RmtPlen = uint8(rmtPlen)
	}
	if lclIP == "" && rmtIP == "" {
		isIPv4 = 1
	}
	rule.IsIP4 = isIPv4

	// Search for the rule.
	for _, rule2 := range table {
		if rule.Compare(rule2, false) == 0 {
			return true
		}
	}
	return false
}

// msgReplyHandler handles binary API request.
func (msr *MockSessionRules) msgReplyHandler(request govppmock.MessageDTO) (reply []byte, msgID uint16, prepared bool) {
	msr.reqCount++
	reqName, found := msr.vppMock.GetMsgNameByID(request.MsgID)
	if !found {
		msr.errCount++
		msr.Log.Error("Not existing req msg name for MsgID=", request.MsgID)
		return reply, 0, false
	}
	msr.Log.Debug("MockSessionRules msgReplyHandler ", request.MsgID, " ", reqName)

	if reqName == "session_rules_dump" {
		// Session dump.
		for _, localTable := range msr.localTable {
			for _, rule := range localTable {
				msr.vppMock.MockReply(makeSessionRuleDetails(rule))
			}
		}
		for _, rule := range msr.globalTable {
			msr.vppMock.MockReply(makeSessionRuleDetails(rule))
		}

	} else if reqName == "control_ping" {
		// Control ping.
		msgID, err := msr.vppMock.GetMsgID("control_ping_reply", "")
		if err != nil {
			msr.errCount++
			msr.Log.Error(err)
			return reply, 0, false
		}
		replyMsg := &vpe.ControlPingReply{}
		replyMsg.Retval = 0
		reply, err := msr.vppMock.ReplyBytes(request, replyMsg)
		if err != nil {
			msr.errCount++
			msr.Log.Error(err)
			return reply, 0, false
		}
		return reply, msgID, true

	} else if reqName == "session_rule_add_del" {
		// Session rule add/del.
		var retval int32

		// Decode rule.
		codec := govpp.MsgCodec{}
		ruleAddDel := session.SessionRuleAddDel{}
		err := codec.DecodeMsg(request.Data, &ruleAddDel)
		if err != nil {
			msr.errCount++
			msr.Log.Error(err)
			return reply, 0, false
		}
		msgID, err := msr.vppMock.GetMsgID("session_rule_add_del_reply", "")
		if err != nil {
			msr.errCount++
			msr.Log.Error(err)
			return reply, 0, false
		}
		rule := makeSessionRule(&ruleAddDel)

		// Check tag
		tagLen := bytes.IndexByte(rule.Tag[:], 0)
		tag := string(rule.Tag[:tagLen])
		if !strings.HasPrefix(tag, msr.tagPrefix) {
			msr.errCount++
			msr.Log.WithField("rule", rule).Warn("Invalid tag")
			retval = 1
		}
		if ruleAddDel.IsAdd == 1 {
			_, alreadyExists := msr.tags[tag]
			if alreadyExists {
				msr.errCount++
				msr.Log.WithField("rule", rule).Warn("Duplicate tag")
				retval = 1
			}
		}

		// Add/Delete rule.
		if retval == 0 {
			var ok bool
			if rule.Scope == cache.RuleScopeLocal {
				_, exists := msr.localTable[rule.AppnsIndex]
				if !exists {
					msr.localTable[rule.AppnsIndex] = SessionRules{}
				}
				msr.localTable[rule.AppnsIndex], ok = addDelRule(msr.localTable[rule.AppnsIndex], rule, ruleAddDel.IsAdd)
				if !ok {
					msr.errCount++
					msr.Log.WithField("rule", rule).Warn("The rule cannot be added/removed to/from the table")
					retval = 1
				}
			} else {
				msr.globalTable, ok = addDelRule(msr.globalTable, rule, ruleAddDel.IsAdd)
				if !ok {
					msr.errCount++
					msr.Log.WithField("rule", rule).Warn("The rule cannot be added/removed to/from the table")
					retval = 1
				}
			}
		}

		// Update the set of used tags.
		if retval == 0 {
			if ruleAddDel.IsAdd == 1 {
				msr.tags[tag] = struct{}{}
			} else {
				delete(msr.tags, tag)
			}
		}

		// Send response.
		replyMsg := session.SessionRuleAddDelReply{}
		replyMsg.Retval = retval
		reply, err := msr.vppMock.ReplyBytes(request, &replyMsg)
		if err != nil {
			msr.errCount++
			msr.Log.Error(err)
			return reply, 0, false
		}
		return reply, msgID, true
	} else {
		msr.Log.WithField("reqName", reqName).Warn("Unhandled request")
	}

	return reply, 0, false
}

// addDelRule adds or removes rule to/from a table.
func addDelRule(table SessionRules, rule *cache.SessionRule, isAdd uint8) (SessionRules, bool) {
	compareTag := false
	if isAdd == 0 {
		compareTag = true /* exact match for removal */
	}
	for idx, rule2 := range table {
		if rule.Compare(rule2, compareTag) == 0 {
			if isAdd == 1 {
				/* already added */
				return table, false
			}
			return append(table[:idx], table[idx+1:]...), true
		}
	}

	if isAdd == 1 {
		return append(table, rule), true
	}
	/* not found */
	return table, false
}

func makeSessionRuleDetails(rule *cache.SessionRule) *session.SessionRulesDetails {
	details := &session.SessionRulesDetails{
		TransportProto: rule.TransportProto,
		IsIP4:          rule.IsIP4,
		LclIP:          rule.LclIP[:],
		LclPlen:        rule.LclPlen,
		RmtIP:          rule.RmtIP[:],
		RmtPlen:        rule.RmtPlen,
		LclPort:        rule.LclPort,
		RmtPort:        rule.RmtPort,
		ActionIndex:    rule.ActionIndex,
		AppnsIndex:     rule.AppnsIndex,
		Scope:          rule.Scope,
		Tag:            rule.Tag[:],
	}
	return details
}

func makeSessionRule(rule *session.SessionRuleAddDel) *cache.SessionRule {
	sessionRule := &cache.SessionRule{
		TransportProto: rule.TransportProto,
		IsIP4:          rule.IsIP4,
		LclPlen:        rule.LclPlen,
		RmtPlen:        rule.RmtPlen,
		LclPort:        rule.LclPort,
		RmtPort:        rule.RmtPort,
		ActionIndex:    rule.ActionIndex,
		AppnsIndex:     rule.AppnsIndex,
		Scope:          rule.Scope,
	}
	copy(sessionRule.LclIP[:], rule.LclIP)
	copy(sessionRule.RmtIP[:], rule.RmtIP)
	copy(sessionRule.Tag[:], rule.Tag)
	return sessionRule
}

// Function returns the IP subnet that contains only the given host
// (i.e. /32 for IPv4, /128 for IPv6).
func getOneHostSubnet(hostAddr string) *net.IPNet {
	ip := net.ParseIP(hostAddr)
	if ip == nil {
		return nil
	}
	ipNet := &net.IPNet{IP: ip}
	if ip.To4() != nil {
		ipNet.Mask = net.CIDRMask(net.IPv4len*8, net.IPv4len*8)
	} else {
		ipNet.Mask = net.CIDRMask(net.IPv6len*8, net.IPv6len*8)
	}
	return ipNet
}
