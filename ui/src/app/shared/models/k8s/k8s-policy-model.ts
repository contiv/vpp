export class K8sPolicyModel {

  public name: string;
  public namespace: string;
  public from: string;
  public to: string;

  constructor(data: any) {
    this.name = data.metadata.name;
    this.namespace = data.metadata.namespace;
    this.from = data.spec.ingress.ipBlock.cidr;
    this.to = data.spec.egress.to.ipBlock.cidr;
  }
}
