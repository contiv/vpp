export class VppIpamModel {

  public nodeId: number;
  public nodeName: string;
  public nodeIP: string;
  public podNetwork: string;
  public vppHostNetwork: string;
  public podIfIPCIDR: string;
  public podSubnetCIDR: string;
  public nodeInterconnectCIDR: string;
  public vxlanCIDR: string;
  public vppHostSubnetCIDR: string;

  constructor(data: any) {
    this.nodeId = data.nodeId;
    this.nodeName = data.nodeName;
    this.nodeIP = data.nodeIP;
    this.podNetwork = data.podSubnetThisNode;
    this.vppHostNetwork = data.vppHostNetwork;

    if (data.config) {
      this.podIfIPCIDR = data.config.serviceCIDR;
      this.podSubnetCIDR = data.config.podSubnetCIDR;
      this.nodeInterconnectCIDR = data.config.nodeInterconnectCIDR;
      this.vxlanCIDR = data.config.vxlanCIDR;
      this.vppHostSubnetCIDR = data.config.vppHostSubnetCIDR;
    }
  }

}
