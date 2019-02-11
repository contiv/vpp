import { Injectable } from '@angular/core';
import { K8sNodeModel } from '../shared/models/k8s/k8s-node-model';
import { K8sPodModel } from '../shared/models/k8s/k8s-pod-model';
import { NodeData } from '../d3-topology/topology/topology-data/interfaces/node-data';
import { EdgeData } from '../d3-topology/topology/topology-data/interfaces/edge-data';
import { ContivDataModel } from '../shared/models/contiv-data-model';
import { LayoutService } from '../shared/services/layout.service';
import { TopologyType } from '../shared/interfaces/topology-type';
import { TopoColors } from '../shared/constants/topo-colors';

@Injectable({
  providedIn: 'root'
})
export class K8sTopologyService {

  constructor(
    private layoutService: LayoutService
  ) { }

  public getTopologyData(data: ContivDataModel): {nodes: NodeData[], links: EdgeData[], type: TopologyType} {
    this.layoutService.podCount = {};
    const nodesTopoData = this.createNodes(data);
    const linksTopoData = this.createLinks(data);

    return {nodes: nodesTopoData, links: linksTopoData, type: 'k8s'};
  }

  private createNodes(data: ContivDataModel): NodeData[] {
    let nodesTopoData: NodeData[] = [];

    data.contivData.forEach(d => {
      const node = this.createTopologyNode(d.node);
      const pods = d.pods.map(p => this.createTopologyPod(p));
      const vswitch = this.createTopologyVswitch(d.vswitch);
      const vppPods = d.vppPods.map(p => this.createTopologyVppPod(p, vswitch));

      nodesTopoData = nodesTopoData.concat([node], pods, [vswitch], vppPods);
    });

    return nodesTopoData;
  }

  private createLinks(data: ContivDataModel): EdgeData[] {
    const nodesLinks = this.layoutService.connectNodes(data);
    const podsLinks = this.layoutService.connectPodsToHost(data);
    const vswitchLinks = this.layoutService.connectVswitchesToHost(data);
    const vppLinks = this.layoutService.connectVppPodsToVswitch(data);

    return [].concat(nodesLinks, podsLinks, vswitchLinks, vppLinks);
  }

  private createTopologyNode(node: K8sNodeModel): NodeData {
    const savedPosition = this.layoutService.getSavedPosition(node.name, 'k8s');
    const position = savedPosition ? savedPosition : this.layoutService.getNodePosition(node);
    return {
      id: node.name,
      label: node.name,
      x: position.x,
      y: position.y,
      stroke: TopoColors.NODE_STROKE,
      nodeType: 'node',
      IP: node.ip
    };
  }

  private createTopologyVswitch(vswitch: K8sPodModel): NodeData {
    const savedPosition = this.layoutService.getSavedPosition(vswitch.name, 'k8s');
    const position = savedPosition ? savedPosition : this.layoutService.getVswitchPosition(vswitch);
    const node: NodeData = {
      id: vswitch.name,
      label: vswitch.name,
      x: position.x,
      y: position.y,
      nodeType: 'vswitch',
      IP: vswitch.podIp,
      namespace: vswitch.namespace,
      stroke: TopoColors.VSWITCH_STROKE
    };

    return node;
  }

  private createTopologyPod(pod: K8sPodModel): NodeData {
    const savedPosition = this.layoutService.getSavedPosition(pod.name, 'k8s');
    const position = savedPosition ? savedPosition : this.layoutService.getPodPosition(pod);
    const node: NodeData = {
      id: pod.name,
      label: pod.name,
      x: position.x,
      y: position.y,
      nodeType: 'pod',
      IP: pod.podIp,
      namespace: pod.namespace
    };

    return node;
  }

  private createTopologyVppPod(pod: K8sPodModel, vswitch: NodeData): NodeData {
    const savedPosition = this.layoutService.getSavedPosition(pod.name, 'k8s');
    const position = savedPosition ? savedPosition : this.layoutService.getPodPosition(pod);
    const node: NodeData = {
      id: pod.name,
      label: pod.name,
      x: position.x,
      y: position.y,
      nodeType: 'vppPod',
      IP: pod.podIp,
      namespace: pod.namespace
    };

    return node;
  }
}
