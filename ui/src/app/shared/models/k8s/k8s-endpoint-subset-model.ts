import { K8sEndpointSubsetData } from './k8s-endpoint-subset-data';

export class K8sEndpointSubsetModel {

  public addresses: K8sEndpointSubsetData[];

  constructor(data: any) {
    if (data.addresses) {
      this.addresses = data.addresses.map(d => new K8sEndpointSubsetData(d));
    }
  }
}
