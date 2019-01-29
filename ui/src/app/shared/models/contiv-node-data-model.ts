import { K8sNodeModel } from './k8s/k8s-node-model';
import { K8sPodModel } from './k8s/k8s-pod-model';
import { VppInterfaceModel } from './vpp/vpp-interface-model';
import { VppIpamModel } from './vpp/vpp-ipam-model';
import { ContivNodeData } from '../interfaces/contiv-node-data';
import { VppBdModel } from './vpp/vpp-bd-model';
import { K8sNamespaceModel } from './k8s/k8s-namespace-model';

export class ContivNodeDataModel implements ContivNodeData {

  public node: K8sNodeModel;
  public vswitch: K8sPodModel;
  public pods: K8sPodModel[];
  public vppPods: K8sPodModel[];
  public interfaces: VppInterfaceModel[];
  public ipam: VppIpamModel;
  public bd: VppBdModel[];
  public namespaces: K8sNamespaceModel[];

  constructor(data: ContivNodeData) {
    Object.keys(data).forEach(prop => this[prop] = data[prop]);
  }

  public getVSwitch(): K8sPodModel {
    return this.pods.find(p => p.name.includes('vswitch'));
  }

  public getBVI(): VppInterfaceModel {
    return this.interfaces.find(i => i.name === 'vxlanBVI');
  }

  public getBVIIp(): string {
    return this.getBVI().IPS.split('/')[0];
  }

  public getInterfaceByName(internalName: string): VppInterfaceModel {
    return this.interfaces.find(i => i.internalName === internalName || i.name === internalName);
  }

  public getVxlans(): VppInterfaceModel[] {
    return this.interfaces.filter(i => i.srcIP && i.dstIP && i.name.includes('vxlan'));
  }

  public getPods(): K8sPodModel[] {
    return this.pods.concat(this.vppPods, this.vswitch);
  }

  public getPodById(podId: string): K8sPodModel {
    return this.getPods().find(pod => pod.name === podId);
  }

  public getTapByInternalName(name: string): VppInterfaceModel {
    return this.interfaces.find(iface => iface.internalName === name);
  }

  public getTapInterfaces(): VppInterfaceModel[] {
    return this.interfaces.filter(i => i.isTap());
  }

  public getGigInterface(): VppInterfaceModel {
    return this.interfaces.find(i => i.isGig());
  }

  public getVppTap(): VppInterfaceModel {
    return this.interfaces.find(i => i.name === 'tap-vpp2');
  }

  public getIpamNodeIp(): string {
    return this.ipam.nodeIP;
  }

}
