export class K8sPodModel {

  public name: string;
  public namespace: string;
  public podIp: string;
  public hostIp: string;
  public node: string;
  public vppIp?: string;
  public tapInterface?: string;
  public tapInternalInterface?: string;

  constructor(data: any) {
    this.name = data.metadata.name;
    this.namespace = data.metadata.namespace;
    this.podIp = data.status.podIP;
    this.hostIp = data.status.hostIP;
    this.node = data.spec.nodeName;
  }

  public isVswitch(): boolean {
    return this.name.includes('vswitch');
  }

  public isVppPod(): boolean {
    return this.hostIp !== this.podIp;
  }

  public getVppIp(): string {
    return this.vppIp.split('/')[0];
  }

}
