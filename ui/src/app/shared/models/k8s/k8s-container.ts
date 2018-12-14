export class K8sContainer {

  public name: string;
  public image: string;

  constructor(data) {
    this.name = data.name;
    this.image = data.image;
  }
}
