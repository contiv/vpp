export class VppArpModel {

  public interface: string;
  public IP: string;
  public MAC: string;
  public static: boolean;
  public swIfIndex: number;

  constructor(data: any) {
    if (data.Arp) {
      this.interface = data.Arp.interface;
      this.IP = data.Arp.ip_address;
      this.MAC = data.Arp.phys_address;
      this.static = data.Arp.static;
    }

    if (data.Meta) {
      this.swIfIndex = data.Meta.SwIfIndex;
    }
  }
}
