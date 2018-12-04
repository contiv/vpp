export class K8sServicePortModel {

  public name: string;
  public protocol: string;
  public port: number;
  public targetPort: number;
  public nodePort: number;

  constructor(data) {
    this.name = data.name;
    this.protocol = data.protocol;
    this.port = data.port;
    this.targetPort = data.targetPort;
    this.nodePort = data.nodePort;
  }
}
