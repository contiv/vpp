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
	Log logging.Logger
	tag string

	vppMock     *govppmock.VppAdapter
	localTable  map[uint32]SessionRules // namespace index -> rules
	globalTable SessionRules
	errCount    int
}

type LocalTableCheck struct {
	nsIndex uint32
	session *MockSessionRules
}

type GlobalTableCheck struct {
	session *MockSessionRules
}

// SessionRules is a list of session rules.
type SessionRules []*cache.SessionRule

// NewMockSessionRules is a constructor for MockSessionRules.
func NewMockSessionRules(log logging.Logger, tag string) *MockSessionRules {
	mock := &MockSessionRules{
		Log:         log,
		tag:         tag,
		vppMock:     &govppmock.VppAdapter{},
		localTable:  make(map[uint32]SessionRules),
		globalTable: SessionRules{},
	}
	mock.vppMock.RegisterBinAPITypes(session.Types)
	mock.vppMock.MockReplyHandler(mock.msgReplyHandler)
	return mock
}

func (msr *MockSessionRules) NewVPPChan() *govppapi.Channel {
	conn, err := govpp.Connect(msr.vppMock)
	if err != nil {
		return nil
	}
	c, _ := conn.NewAPIChannel()
	return c
}

func (msr *MockSessionRules) GetErrCount() int {
	return msr.errCount
}

func (msr *MockSessionRules) LocalTable(nsIndex uint32) *LocalTableCheck {
	return &LocalTableCheck{nsIndex: nsIndex, session: msr}
}

func (msr *MockSessionRules) GlobalTable() *GlobalTableCheck {
	return &GlobalTableCheck{session: msr}
}

func (ltc *LocalTableCheck) NumOfRules() int {
	table, exists := ltc.session.localTable[ltc.nsIndex]
	if !exists {
		return 0
	}
	return len(table)
}

func (gtc *GlobalTableCheck) NumOfRules() int {
	return len(gtc.session.globalTable)
}

func (ltc *LocalTableCheck) HasRule(lclIP string, lclPort uint16, rmtIP string, rmtPort uint16, proto string, action string) bool {
	table, exists := ltc.session.localTable[ltc.nsIndex]
	if !exists {
		return false
	}
	return ltc.session.hasRule(table, cache.RuleScopeLocal, ltc.nsIndex, lclIP, lclPort, rmtIP, rmtPort, proto, action)
}

func (gtc *GlobalTableCheck) HasRule(lclIP string, lclPort uint16, rmtIP string, rmtPort uint16, proto string, action string) bool {
	return gtc.session.hasRule(gtc.session.globalTable, cache.RuleScopeGlobal, 0, lclIP, lclPort, rmtIP, rmtPort, proto, action)
}

func (msr *MockSessionRules) hasRule(table SessionRules, scope uint8, nsIndex uint32,
	lclIP string, lclPort uint16, rmtIP string, rmtPort uint16, proto string, action string) bool {

	var err error

	// Construct SessionRule.
	rule := cache.SessionRule{
		LclPort:    lclPort,
		RmtPort:    rmtPort,
		AppnsIndex: nsIndex,
		Scope:      scope,
		Tag:        []byte(msr.tag),
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
		rule.LclIP = lclIPNet.IP
		lclPlen, _ := lclIPNet.Mask.Size()
		rule.LclPlen = uint8(lclPlen)
		if lclIPNet.IP.To4() != nil {
			isIPv4 = 1
		}
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
		rule.RmtIP = rmtIPNet.IP
		rmtPlen, _ := rmtIPNet.Mask.Size()
		rule.RmtPlen = uint8(rmtPlen)
		if rmtIPNet.IP.To4() != nil {
			isIPv4 = 1
		}
	}
	if lclIP == "" && rmtIP == "" {
		isIPv4 = 1
	}
	rule.IsIP4 = isIPv4

	// Search for the rule.
	for _, rule2 := range table {
		if rule.Compare(rule2) == 0 {
			return true
		}
	}
	return false
}

func (msr *MockSessionRules) msgReplyHandler(request govppmock.MessageDTO) (reply []byte, msgID uint16, prepared bool) {
	reqName, found := msr.vppMock.GetMsgNameByID(request.MsgID)
	if !found {
		msr.errCount++
		msr.Log.Error("Not existing req msg name for MsgID=", request.MsgID)
		return reply, 0, false
	}
	msr.Log.Debug("MockSessionRules msgReplyHandler ", request.MsgID, " ", reqName)

	if reqName == "session_rules_dump" {
		for _, localTable := range msr.localTable {
			for _, rule := range localTable {
				msr.vppMock.MockReply(makeSessionRuleDetails(rule))
			}
		}
		for _, rule := range msr.globalTable {
			msr.vppMock.MockReply(makeSessionRuleDetails(rule))
		}
		msr.vppMock.MockReply(&vpe.ControlPingReply{})
		return reply, 0, false

	} else if reqName == "session_rule_add_del" {
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
		tagLen := bytes.IndexByte(rule.Tag, 0)
		tag := string(rule.Tag[:tagLen])
		if tag != msr.tag {
			msr.errCount++
			msr.Log.WithField("rule", rule).Warn("Invalid tag")
			retval = 1
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

func addDelRule(table SessionRules, rule *cache.SessionRule, isAdd uint8) (SessionRules, bool) {
	for idx, rule2 := range table {
		if rule.Compare(rule2) == 0 {
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
		LclIP:          rule.LclIP,
		LclPlen:        rule.LclPlen,
		RmtIP:          rule.RmtIP,
		RmtPlen:        rule.RmtPlen,
		LclPort:        rule.LclPort,
		RmtPort:        rule.RmtPort,
		ActionIndex:    rule.ActionIndex,
		AppnsIndex:     rule.AppnsIndex,
		Scope:          rule.Scope,
		Tag:            rule.Tag,
	}
	return details
}

func makeSessionRule(rule *session.SessionRuleAddDel) *cache.SessionRule {
	sessionRule := &cache.SessionRule{
		TransportProto: rule.TransportProto,
		IsIP4:          rule.IsIP4,
		LclIP:          rule.LclIP,
		LclPlen:        rule.LclPlen,
		RmtIP:          rule.RmtIP,
		RmtPlen:        rule.RmtPlen,
		LclPort:        rule.LclPort,
		RmtPort:        rule.RmtPort,
		ActionIndex:    rule.ActionIndex,
		AppnsIndex:     rule.AppnsIndex,
		Scope:          rule.Scope,
		Tag:            rule.Tag,
	}
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
