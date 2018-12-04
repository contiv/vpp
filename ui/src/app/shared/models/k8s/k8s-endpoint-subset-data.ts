export class K8sEndpointSubsetData {

  public podIp: string;
  public podName: string;
  public namespace: string;
  public nodeName: string;
  public hostIp: string;
  public labels: string;
  public kind: string;
  public vppMapped: boolean;

  constructor(data: any) {
    if (data) {
      this.podIp = data.ip;
      this.nodeName = data.nodeName;

      if (data.targetRef) {
        this.podName = data.targetRef.name;
        this.kind = data.targetRef.kind;
        this.namespace = data.targetRef.namespace;
      }
    }
  }
}
