export class VppInterfaceModel {

  public name: string;
  public mac: string;
  public IPS: string;
  public vrf: number;
  public type: string;
  public mtu: number;
  public enabled: boolean;
  public internalName: string;
  public key: string;
  public srcIP: string;
  public dstIP: string;
  public vni: number;

  constructor(data: any) {
    this.key = data._key;

    if (data.interface) {
      this.name = data.interface.name;
      this.mac = data.interface.physAddress;

      if (data.interface.ipAddresses) {
        this.IPS = data.interface.ipAddresses.join(',');
      }
      this.vrf = data.interface.vrf;
      this.type = data.interface.type;
      this.mtu = data.interface.mtu;
      this.enabled = data.interface.enabled;

      if (data.interface.vxlan) {
        this.srcIP = data.interface.vxlan.srcAddress;
        this.dstIP = data.interface.vxlan.dstAddress;
        this.vni = data.interface.vxlan.vni;
      }

      if (data.interface_meta) {
        this.internalName = data.interface_meta.internal_name;
      }
    }
  }

  public getIP(): string {
    return this.IPS ? this.IPS.split('/')[0] : '';
  }

  public isVxtunnel(): boolean {
    if (this.srcIP && this.dstIP) {
      return true;
    } else {
      return false;
    }
  }

  public isTap(): boolean {
    return this.name && this.name.includes('tap') && this.vrf > 0;
  }

  public isGig(): boolean {
    return this.type === 'DPDK';
  }

  public isBVI(): boolean {
    return this.name && this.name.includes('BVI');
  }
}
