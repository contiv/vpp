export class K8sNodeModel {

  public name: string;
  public ip: string;

  constructor(data: any) {
    this.name = data.metadata.name;
    this.ip = data.status.addresses[0].address;
  }

  public isMaster(): boolean {
    return this.name === 'k8s-master';
  }

}
