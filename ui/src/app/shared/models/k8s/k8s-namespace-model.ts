export class K8sNamespaceModel {
  name: string;
  status: string;

  constructor(data: any) {
    if (data.metadata) {
      this.name = data.metadata.name;
    }

    if (data.status) {
      this.status = data.status.phase;
    }
  }
}
