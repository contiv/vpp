import { ContivNodeDataModel } from './contiv-node-data-model';
import { K8sNodeModel } from './k8s/k8s-node-model';
import { K8sPodModel } from './k8s/k8s-pod-model';
import { ContivNodeData } from '../interfaces/contiv-node-data';
import { VppInterfaceModel } from './vpp/vpp-interface-model';
import { K8sNamespaceModel } from './k8s/k8s-namespace-model';

export class ContivDataModel {

  public contivData: ContivNodeDataModel[];

  constructor() {
    this.contivData = [];
  }

  public addData(data: ContivNodeData) {
    const contivData = new ContivNodeDataModel(data);
    this.contivData.push(contivData);
  }

  public getK8sMasterNode(): K8sNodeModel {
    return this.contivData.find(n => n.node.isMaster()).node;
  }

  public getK8sNodes(): K8sNodeModel[] {
    const nodes: K8sNodeModel[] = [];

    this.contivData.forEach(d => nodes.push(d.node));

    return nodes;
  }

  public getDomainByNodeId(nodeId: string): ContivNodeDataModel {
    return this.contivData.find(cd => cd.node.name === nodeId);
  }

  public getDomainByVswitchId(vswitch: string): ContivNodeDataModel {
    return this.contivData.find(cd => cd.vswitch.name === vswitch.split('-bvi')[0]);
  }

  public getDomainByPodId(podId: string): ContivNodeDataModel {
    return this.contivData.find(cd => cd.getPods().some(pod => pod.name === podId));
  }

  public getPodById(podId: string): K8sPodModel {
    const pods = this.getAllPods();
    return pods.find(p => p.name === podId);
  }

  public getAllPods(): K8sPodModel[] {
    return this.getVppPods().concat(this.getK8sPods()).concat(this.getVswitches());
  }

  public getK8sPods(): K8sPodModel[] {
    let pods: K8sPodModel[] = [];

    this.contivData.forEach(d => pods = pods.concat(d.pods));

    return pods;
  }

  public getNamespaces(): K8sNamespaceModel[] {
    return this.contivData[0].namespaces;
  }

  public getVppPods(): K8sPodModel[] {
    let pods: K8sPodModel[] = [];

    this.contivData.forEach(d => pods = pods.concat(d.vppPods));

    return pods;
  }

  public getVswitches(): K8sPodModel[] {
    return this.contivData.map(d => d.vswitch);
  }

  public getAllBVIs(): VppInterfaceModel[] {
    return this.contivData.map(d => d.interfaces.find(i => i.name === 'vxlanBVI'));
  }

  public getVswitchByVppIp(ip: string): K8sPodModel {
    return this.contivData.find(data => {
      return data.ipam.nodeIP === ip;
    }).vswitch;
  }

  public getNodeByIpamIp(ip: string): K8sNodeModel {
    return this.contivData.find(d => d.ipam.nodeIP === ip).node;
  }

  public getVxlanMapping(): {from: string, to: string}[] {
    let mappings: {from: string, to: string}[] = [];

    this.contivData.forEach(data => {
      const vxlans = data.getVxlans().map(vxlan => {
        return {
          from: data.vswitch.name,
          to: this.getVswitchByVppIp(vxlan.dstIP).name
        };
      });

      mappings = mappings.concat(vxlans);
    });

    return mappings;
  }

  public getVppPodsMapping(): {from: string, to: string}[] {
    let mappings: {from: string, to: string}[] = [];

    this.contivData.forEach(data => {
      const pods = data.vppPods.map(pod => {
        return {
          from: data.vswitch.name,
          to: pod.name
        };
      });

      mappings = mappings.concat(pods);
    });

    return mappings;
  }

  public getVxlansByIps(ip1: string, ip2: string): VppInterfaceModel[] {
    const vxlans: VppInterfaceModel[] = [];

    this.contivData.forEach(d => {
      const vxlan = d.getVxlans().find(v => v.srcIP === ip1 && v.dstIP === ip2 || v.dstIP === ip1 && v.srcIP === ip2);
       if (vxlan) {
         vxlans.push(vxlan);
       }
    });

    return vxlans;
  }

}
