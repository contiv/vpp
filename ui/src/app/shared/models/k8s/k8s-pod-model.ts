import { K8sContainer } from './k8s-container';

export class K8sPodModel {

  public name: string;
  public namespace: string;
  public podIp: string;
  public hostIp: string;
  public node: string;
  public vppIp?: string;
  public tapInterface?: string;
  public tapInternalInterface?: string;

  public containers: K8sContainer[];

  constructor(data: any) {
    if (data.metadata) {
      this.name = data.metadata.name;
      this.namespace = data.metadata.namespace;
    }

    if (data.status) {
      this.podIp = data.status.podIP;
      this.hostIp = data.status.hostIP;
    }

    if (data.spec) {
      this.node = data.spec.nodeName;
      this.containers = data.spec.containers.map(c => new K8sContainer(c));
    }
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
