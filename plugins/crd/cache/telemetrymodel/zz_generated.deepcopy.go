// +build !ignore_autogenerated

// Copyright (c) 2018 Cisco and/or its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by deepcopy-gen. DO NOT EDIT.

package telemetrymodel

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in BdID2NameMapping) DeepCopyInto(out *BdID2NameMapping) {
	{
		in := &in
		*out = make(BdID2NameMapping, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
		return
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BdID2NameMapping.
func (in BdID2NameMapping) DeepCopy() BdID2NameMapping {
	if in == nil {
		return nil
	}
	out := new(BdID2NameMapping)
	in.DeepCopyInto(out)
	return *out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BdInterface) DeepCopyInto(out *BdInterface) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BdInterface.
func (in *BdInterface) DeepCopy() *BdInterface {
	if in == nil {
		return nil
	}
	out := new(BdInterface)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BridgeDomain) DeepCopyInto(out *BridgeDomain) {
	*out = *in
	if in.Interfaces != nil {
		in, out := &in.Interfaces, &out.Interfaces
		*out = make([]BdInterface, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BridgeDomain.
func (in *BridgeDomain) DeepCopy() *BridgeDomain {
	if in == nil {
		return nil
	}
	out := new(BridgeDomain)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BridgeDomainMeta) DeepCopyInto(out *BridgeDomainMeta) {
	*out = *in
	if in.BdID2Name != nil {
		in, out := &in.BdID2Name, &out.BdID2Name
		*out = make(BdID2NameMapping, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BridgeDomainMeta.
func (in *BridgeDomainMeta) DeepCopy() *BridgeDomainMeta {
	if in == nil {
		return nil
	}
	out := new(BridgeDomainMeta)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IPArpEntry) DeepCopyInto(out *IPArpEntry) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IPArpEntry.
func (in *IPArpEntry) DeepCopy() *IPArpEntry {
	if in == nil {
		return nil
	}
	out := new(IPArpEntry)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IPArpEntryMeta) DeepCopyInto(out *IPArpEntryMeta) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IPArpEntryMeta.
func (in *IPArpEntryMeta) DeepCopy() *IPArpEntryMeta {
	if in == nil {
		return nil
	}
	out := new(IPArpEntryMeta)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IPRoute) DeepCopyInto(out *IPRoute) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IPRoute.
func (in *IPRoute) DeepCopy() *IPRoute {
	if in == nil {
		return nil
	}
	out := new(IPRoute)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IPRouteMeta) DeepCopyInto(out *IPRouteMeta) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IPRouteMeta.
func (in *IPRouteMeta) DeepCopy() *IPRouteMeta {
	if in == nil {
		return nil
	}
	out := new(IPRouteMeta)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Interface) DeepCopyInto(out *Interface) {
	*out = *in
	if in.IPAddresses != nil {
		in, out := &in.IPAddresses, &out.IPAddresses
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	out.Vxlan = in.Vxlan
	out.Tap = in.Tap
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Interface.
func (in *Interface) DeepCopy() *Interface {
	if in == nil {
		return nil
	}
	out := new(Interface)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *InterfaceMeta) DeepCopyInto(out *InterfaceMeta) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new InterfaceMeta.
func (in *InterfaceMeta) DeepCopy() *InterfaceMeta {
	if in == nil {
		return nil
	}
	out := new(InterfaceMeta)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *L2FibEntry) DeepCopyInto(out *L2FibEntry) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new L2FibEntry.
func (in *L2FibEntry) DeepCopy() *L2FibEntry {
	if in == nil {
		return nil
	}
	out := new(L2FibEntry)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *L2FibEntryMeta) DeepCopyInto(out *L2FibEntryMeta) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new L2FibEntryMeta.
func (in *L2FibEntryMeta) DeepCopy() *L2FibEntryMeta {
	if in == nil {
		return nil
	}
	out := new(L2FibEntryMeta)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Node) DeepCopyInto(out *Node) {
	*out = *in
	if in.NodeLiveness != nil {
		in, out := &in.NodeLiveness, &out.NodeLiveness
		*out = new(NodeLiveness)
		**out = **in
	}
	if in.NodeInterfaces != nil {
		in, out := &in.NodeInterfaces, &out.NodeInterfaces
		*out = make(map[int]NodeInterface, len(*in))
		for key, val := range *in {
			(*out)[key] = *val.DeepCopy()
		}
	}
	if in.NodeBridgeDomains != nil {
		in, out := &in.NodeBridgeDomains, &out.NodeBridgeDomains
		*out = make(map[int]NodeBridgeDomain, len(*in))
		for key, val := range *in {
			(*out)[key] = *val.DeepCopy()
		}
	}
	if in.NodeL2Fibs != nil {
		in, out := &in.NodeL2Fibs, &out.NodeL2Fibs
		*out = make(map[string]NodeL2FibEntry, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.NodeTelemetry != nil {
		in, out := &in.NodeTelemetry, &out.NodeTelemetry
		*out = make(map[string]NodeTelemetry, len(*in))
		for key, val := range *in {
			(*out)[key] = *val.DeepCopy()
		}
	}
	if in.NodeIPArp != nil {
		in, out := &in.NodeIPArp, &out.NodeIPArp
		*out = make([]NodeIPArpEntry, len(*in))
		copy(*out, *in)
	}
	if in.NodeStaticRoutes != nil {
		in, out := &in.NodeStaticRoutes, &out.NodeStaticRoutes
		*out = make([]NodeIPRoute, len(*in))
		copy(*out, *in)
	}
	if in.Report != nil {
		in, out := &in.Report, &out.Report
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.PodMap != nil {
		in, out := &in.PodMap, &out.PodMap
		*out = make(map[string]*Pod, len(*in))
		for key, val := range *in {
			var outVal *Pod
			if val == nil {
				(*out)[key] = nil
			} else {
				in, out := &val, &outVal
				*out = new(Pod)
				(*in).DeepCopyInto(*out)
			}
			(*out)[key] = outVal
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Node.
func (in *Node) DeepCopy() *Node {
	if in == nil {
		return nil
	}
	out := new(Node)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NodeBridgeDomain) DeepCopyInto(out *NodeBridgeDomain) {
	*out = *in
	in.Bd.DeepCopyInto(&out.Bd)
	in.BdMeta.DeepCopyInto(&out.BdMeta)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodeBridgeDomain.
func (in *NodeBridgeDomain) DeepCopy() *NodeBridgeDomain {
	if in == nil {
		return nil
	}
	out := new(NodeBridgeDomain)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in NodeBridgeDomains) DeepCopyInto(out *NodeBridgeDomains) {
	{
		in := &in
		*out = make(NodeBridgeDomains, len(*in))
		for key, val := range *in {
			(*out)[key] = *val.DeepCopy()
		}
		return
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodeBridgeDomains.
func (in NodeBridgeDomains) DeepCopy() NodeBridgeDomains {
	if in == nil {
		return nil
	}
	out := new(NodeBridgeDomains)
	in.DeepCopyInto(out)
	return *out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NodeIPArpEntry) DeepCopyInto(out *NodeIPArpEntry) {
	*out = *in
	out.Ae = in.Ae
	out.AeMeta = in.AeMeta
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodeIPArpEntry.
func (in *NodeIPArpEntry) DeepCopy() *NodeIPArpEntry {
	if in == nil {
		return nil
	}
	out := new(NodeIPArpEntry)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in NodeIPArpTable) DeepCopyInto(out *NodeIPArpTable) {
	{
		in := &in
		*out = make(NodeIPArpTable, len(*in))
		copy(*out, *in)
		return
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodeIPArpTable.
func (in NodeIPArpTable) DeepCopy() NodeIPArpTable {
	if in == nil {
		return nil
	}
	out := new(NodeIPArpTable)
	in.DeepCopyInto(out)
	return *out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NodeIPRoute) DeepCopyInto(out *NodeIPRoute) {
	*out = *in
	out.Ipr = in.Ipr
	out.IprMeta = in.IprMeta
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodeIPRoute.
func (in *NodeIPRoute) DeepCopy() *NodeIPRoute {
	if in == nil {
		return nil
	}
	out := new(NodeIPRoute)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NodeInterface) DeepCopyInto(out *NodeInterface) {
	*out = *in
	in.If.DeepCopyInto(&out.If)
	out.IfMeta = in.IfMeta
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodeInterface.
func (in *NodeInterface) DeepCopy() *NodeInterface {
	if in == nil {
		return nil
	}
	out := new(NodeInterface)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in NodeInterfaces) DeepCopyInto(out *NodeInterfaces) {
	{
		in := &in
		*out = make(NodeInterfaces, len(*in))
		for key, val := range *in {
			(*out)[key] = *val.DeepCopy()
		}
		return
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodeInterfaces.
func (in NodeInterfaces) DeepCopy() NodeInterfaces {
	if in == nil {
		return nil
	}
	out := new(NodeInterfaces)
	in.DeepCopyInto(out)
	return *out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NodeL2FibEntry) DeepCopyInto(out *NodeL2FibEntry) {
	*out = *in
	out.Fe = in.Fe
	out.FeMeta = in.FeMeta
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodeL2FibEntry.
func (in *NodeL2FibEntry) DeepCopy() *NodeL2FibEntry {
	if in == nil {
		return nil
	}
	out := new(NodeL2FibEntry)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in NodeL2FibTable) DeepCopyInto(out *NodeL2FibTable) {
	{
		in := &in
		*out = make(NodeL2FibTable, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
		return
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodeL2FibTable.
func (in NodeL2FibTable) DeepCopy() NodeL2FibTable {
	if in == nil {
		return nil
	}
	out := new(NodeL2FibTable)
	in.DeepCopyInto(out)
	return *out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NodeLiveness) DeepCopyInto(out *NodeLiveness) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodeLiveness.
func (in *NodeLiveness) DeepCopy() *NodeLiveness {
	if in == nil {
		return nil
	}
	out := new(NodeLiveness)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in NodeStaticRoutes) DeepCopyInto(out *NodeStaticRoutes) {
	{
		in := &in
		*out = make(NodeStaticRoutes, len(*in))
		copy(*out, *in)
		return
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodeStaticRoutes.
func (in NodeStaticRoutes) DeepCopy() NodeStaticRoutes {
	if in == nil {
		return nil
	}
	out := new(NodeStaticRoutes)
	in.DeepCopyInto(out)
	return *out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in NodeTelemetries) DeepCopyInto(out *NodeTelemetries) {
	{
		in := &in
		*out = make(NodeTelemetries, len(*in))
		for key, val := range *in {
			(*out)[key] = *val.DeepCopy()
		}
		return
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodeTelemetries.
func (in NodeTelemetries) DeepCopy() NodeTelemetries {
	if in == nil {
		return nil
	}
	out := new(NodeTelemetries)
	in.DeepCopyInto(out)
	return *out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NodeTelemetry) DeepCopyInto(out *NodeTelemetry) {
	*out = *in
	if in.Output != nil {
		in, out := &in.Output, &out.Output
		*out = make([]Output, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodeTelemetry.
func (in *NodeTelemetry) DeepCopy() *NodeTelemetry {
	if in == nil {
		return nil
	}
	out := new(NodeTelemetry)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Output) DeepCopyInto(out *Output) {
	*out = *in
	if in.output != nil {
		in, out := &in.output, &out.output
		*out = make([]OutputEntry, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Output.
func (in *Output) DeepCopy() *Output {
	if in == nil {
		return nil
	}
	out := new(Output)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OutputEntry) DeepCopyInto(out *OutputEntry) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OutputEntry.
func (in *OutputEntry) DeepCopy() *OutputEntry {
	if in == nil {
		return nil
	}
	out := new(OutputEntry)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Pod) DeepCopyInto(out *Pod) {
	*out = *in
	if in.Label != nil {
		in, out := &in.Label, &out.Label
		*out = make([]*PodLabel, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(PodLabel)
				**out = **in
			}
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Pod.
func (in *Pod) DeepCopy() *Pod {
	if in == nil {
		return nil
	}
	out := new(Pod)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PodLabel) DeepCopyInto(out *PodLabel) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PodLabel.
func (in *PodLabel) DeepCopy() *PodLabel {
	if in == nil {
		return nil
	}
	out := new(PodLabel)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in Reports) DeepCopyInto(out *Reports) {
	{
		in := &in
		*out = make(Reports, len(*in))
		for key, val := range *in {
			var outVal []string
			if val == nil {
				(*out)[key] = nil
			} else {
				in, out := &val, &outVal
				*out = make([]string, len(*in))
				copy(*out, *in)
			}
			(*out)[key] = outVal
		}
		return
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Reports.
func (in Reports) DeepCopy() Reports {
	if in == nil {
		return nil
	}
	out := new(Reports)
	in.DeepCopyInto(out)
	return *out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Tap) DeepCopyInto(out *Tap) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Tap.
func (in *Tap) DeepCopy() *Tap {
	if in == nil {
		return nil
	}
	out := new(Tap)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Vxlan) DeepCopyInto(out *Vxlan) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Vxlan.
func (in *Vxlan) DeepCopy() *Vxlan {
	if in == nil {
		return nil
	}
	out := new(Vxlan)
	in.DeepCopyInto(out)
	return out
}
