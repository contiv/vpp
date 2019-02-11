import { K8sEndpointSubsetModel } from './k8s-endpoint-subset-model';
import { K8sKeyValueModel } from './k8s-key-value-model';

export class K8sEndpointModel {

  public name: string;
  public namespace: string;
  public subsets: K8sEndpointSubsetModel[];
  public labels: K8sKeyValueModel[];

  constructor(data: any) {

    if (data.metadata) {
      this.name = data.metadata.name;
      this.namespace = data.metadata.namespace;

      if (data.metadata.labels) {
        this.labels = this.createKeyValuePairs(data.metadata.labels);
      }
    }

    if (data.subsets) {
      this.subsets = data.subsets.map(s => new K8sEndpointSubsetModel(s));
    }
  }

  private createKeyValuePairs(data): K8sKeyValueModel[] {
    return Object.keys(data).map(k => new K8sKeyValueModel(k, data[k]));
  }
}
