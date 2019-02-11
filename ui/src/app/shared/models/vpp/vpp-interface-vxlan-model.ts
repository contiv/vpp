export class VppInterfaceVxlanModel {

  public name: string;
  public type: string;
  public enabled: boolean;
  public vrf: number;
  public srcIp: string;
  public dstIp: string;
  public vni: number;
  public key: string;

  constructor(data: any) {
    this.key = data._key;

    if (data.interface) {
      this.name = data.interface.name;
      this.type = data.interface.type;
      this.enabled = data.interface.enabled;
      this.vrf = data.interface.vrf;

      if (data.interface.vxlan) {
        this.srcIp = data.interface.vxlan.srcAddress;
        this.dstIp = data.interface.vxlan.dstAddress;
        this.vni = data.interface.vxlan.vni;
      }
    }
  }

}
