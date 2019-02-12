export class K8sNodeModel {

  public name: string;
  public ip: string;
  public role: string;

  constructor(data: any) {
    this.name = data.metadata.name;
    this.ip = data.status.addresses[0].address;
    this.role = 'none';

    if (data.metadata.labels) {
      Object.keys(data.metadata.labels).forEach(label => {
        if (label.startsWith('node-role.kubernetes.io')) {
          this.role = label.split('/')[1];
        }
      });
    }
  }

  public isMaster(): boolean {
    return this.role === 'master';
  }

}
