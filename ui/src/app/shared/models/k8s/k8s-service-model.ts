import { K8sKeyValueModel } from './k8s-key-value-model';
import { K8sServicePortModel } from './k8s-service-port-model';

export class K8sServiceModel {

  public name: string;
  public namespace: string;
  public labels: K8sKeyValueModel[];
  public selectors: K8sKeyValueModel[];
  public clusterIp: string;
  public timestamp: string;
  public ports: K8sServicePortModel[];

  constructor(data: any) {

    if (data.metadata) {
      this.name = data.metadata.name;
      this.namespace = data.metadata.namespace;
      this.timestamp = data.metadata.creationTimestamp;

      if (data.metadata.labels) {
        this.labels = this.createKeyValuePairs(data.metadata.labels);
      }
    }

    if (data.spec) {
      this.clusterIp = data.spec.clusterIP;

      if (data.spec.ports) {
        this.ports = this.createPorts(data.spec.ports);
      }

      if (data.spec.selector) {
        this.selectors = this.createKeyValuePairs(data.spec.selector);
      }
    }
  }

  private createKeyValuePairs(data): K8sKeyValueModel[] {
    return Object.keys(data).map(k => new K8sKeyValueModel(k, data[k]));
  }

  private createPorts(data: any[]) {
    return data.map(d => new K8sServicePortModel(d));
  }

}
