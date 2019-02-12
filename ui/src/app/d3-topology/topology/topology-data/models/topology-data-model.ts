import { NodeDataModel } from './node-data-model';
import { EdgeDataModel } from './edge-data-model';
import { NodeData } from '../interfaces/node-data';
import { EdgeData } from '../interfaces/edge-data';
import { K8sTopoNode } from './nodes/k8s-topo-node';
import { K8sTopoPod } from './nodes/k8s-topo-pod';
import { VppTopoTap } from './nodes/vpp-topo-tap';
import { VppTopoPod } from './nodes/vpp-topo-pod';
import { VppTopoVswitch } from './nodes/vpp-topo-vswitch';
import { VppTopoBvi } from './nodes/vpp-topo-bvi';

export class TopologyDataModel {

  public nodes: NodeDataModel[];
  public links: EdgeDataModel[];

  public setData(nodesData: NodeData[], linksData: EdgeData[]) {
    if (nodesData && nodesData.length) {
      nodesData.forEach(nd => {
        switch (nd.nodeType) {
          case 'node':
            this.nodes.push(new K8sTopoNode(nd));
            break;
          case 'pod':
            this.nodes.push(new K8sTopoPod(nd));
            break;
          case 'iface':
            this.nodes.push(new VppTopoTap(nd));
            break;
          case 'vppPod':
            this.nodes.push(new VppTopoPod(nd));
            break;
          case 'vswitch':
            this.nodes.push(new VppTopoVswitch(nd));
            break;
          case 'bvi':
            this.nodes.push(new VppTopoBvi(nd));
            break;
        }
      });
    }

    if (linksData && linksData.length) {
      linksData.forEach(ld => {
        switch (ld.fromType) {
          case 'node':
            ld.fromNodeObj = this.getNodeById(ld.from);
            break;
          case 'vxlan':
            ld.fromNodeObj = this.getBVIById(ld.from);
            break;
        }

        switch (ld.toType) {
          case 'node':
            ld.toNodeObj = this.getNodeById(ld.to);
            break;
          case 'vxlan':
            ld.toNodeObj = this.getBVIById(ld.to);
            break;
        }

        const link = new EdgeDataModel(ld);
        this.links.push(link);
      });
    }
  }

  public getNodeById(nodeId: string): NodeDataModel {
    return this.nodes.filter(
      (node: NodeDataModel) => node.id === nodeId
    )[0];
  }

  public getNodeByName(nodeName: string): NodeDataModel {
    return this.nodes.filter(
      (node: NodeDataModel) => node.label === nodeName.trim()
    )[0];
  }

  public getBVIById(bviId: string): NodeDataModel {
    return this.nodes.find(
      (bvi: NodeDataModel) => bvi.id === bviId
    );
  }

  public getLinksByNodes(node1: NodeDataModel, node2: NodeDataModel): EdgeDataModel[] {
    return this.links.filter(
      (link: EdgeDataModel) => link.from === node1.id && link.to === node2.id
                                    || link.from === node2.id && link.to === node1.id
    );
  }

  public getLinksByNode(node: NodeDataModel): EdgeDataModel[] {
    return this.links.filter(
      link => link.from === node.id || link.to === node.id
    );
  }

  public getLinkById(id: string): EdgeDataModel {
    return this.links.filter(link => link.id === id)[0];
  }

  public getNeighboringLinks(node: NodeDataModel): Array<EdgeDataModel> {
    return this.links.filter(link =>
      link.fromNodeObj === node || link.toNodeObj === node
    );
  }

  public getNeighboringNodes(node: NodeDataModel): Array<NodeDataModel> {
    const links = this.getNeighboringLinks(node);
    const nodes = [];

    links.forEach(link => {
      if (link.fromNodeObj === node) { nodes.push(link.toNodeObj); }
      if (link.toNodeObj === node) { nodes.push(link.fromNodeObj); }
    });

    return nodes;
  }

  public removeNodeByNode(node: NodeDataModel) {
    this.nodes.splice(this.nodes.findIndex(n => n.id === node.id), 1);
  }

  public removeLinkByLink(link: EdgeDataModel) {
    this.links.splice(this.links.indexOf(link), 1);
  }

  public removeLinksByNodeId(nodeId: string) {
    this.links = this.links.filter(
      link => {
        return (link.from !== nodeId && link.to !== nodeId);
      }
    );
  }

  constructor() {
    this.nodes = [];
    this.links = [];
  }
}
