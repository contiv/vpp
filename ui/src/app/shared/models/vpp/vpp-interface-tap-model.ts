export class VppInterfaceTapModel {

  public name: string;
  public type: string;
  public enabled: boolean;
  public MAC: string;
  public mtu: number;
  public IPS: string;
  public tapVersion: number;
  public key: string;
  public internalName: string;

  constructor(data: any) {
    this.key = data._key;

    if (data.interface) {
      this.name = data.interface.name;
      this.MAC = data.interface.physAddress;

      if (data.interface.ipAddresses) {
        this.IPS = data.interface.ipAddresses.join(',');
      }

      this.type = data.interface.type;
      this.mtu = data.interface.mtu;
      this.enabled = data.interface.enabled;

      if (data.interface.tap) {
        this.tapVersion = data.interface.tap.version;
      }
    }

    if (data.interface_meta) {
      this.internalName = data.interface_meta.internal_name;
    }
  }
}
