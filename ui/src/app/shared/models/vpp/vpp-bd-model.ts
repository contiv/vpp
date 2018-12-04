export class VppBdModel {

  public name: string;
  public forward: boolean;
  public interfaces: string[];
  public key: string;

  constructor(data: any) {
    this.key = data._key;

    if (data.bridge_domain) {
      this.name = data.bridge_domain.name;
      this.forward = data.bridge_domain.forward;
      this.interfaces = data.bridge_domain.interfaces.map(i => i.name);
    }
  }

}
