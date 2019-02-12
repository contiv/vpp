import { Injectable } from '@angular/core';
import { LayoutService } from '../shared/services/layout.service';
import { ContivDataModel } from '../shared/models/contiv-data-model';
import { NodeData } from '../d3-topology/topology/topology-data/interfaces/node-data';
import { EdgeData } from '../d3-topology/topology/topology-data/interfaces/edge-data';
import { TopologyType } from '../shared/interfaces/topology-type';
import { TopoColors } from '../shared/constants/topo-colors';
import { K8sPodModel } from '../shared/models/k8s/k8s-pod-model';
import { VppInterfaceModel } from '../shared/models/vpp/vpp-interface-model';

@Injectable({
  providedIn: 'root'
})
export class BridgeDomainService {

  constructor(
    private layoutService: LayoutService
  ) { }

  public getTopologyData(data: ContivDataModel): {nodes: NodeData[], links: EdgeData[], type: TopologyType} {
    this.layoutService.podCount = {};
    const nodesTopoData = this.createNodes(data);
    const linksTopoData = this.createLinks(data);

    return {nodes: nodesTopoData, links: linksTopoData, type: 'bd'};
  }

  private createNodes(data: ContivDataModel): NodeData[] {
    let nodesTopoData: NodeData[] = [];

    data.contivData.forEach(d => {
      const vswitch = this.createTopologyVswitch(d.vswitch);
      const vppPods = d.vppPods.map(p => this.createTopologyVppPod(p, vswitch));
      const bvi = this.createTopologyBVI(d.getBVI(), vswitch);

      nodesTopoData = nodesTopoData.concat([vswitch], vppPods, [bvi]);
    });

    return nodesTopoData;
  }

  private createLinks(data: ContivDataModel): EdgeData[] {
    const vppLinks = this.layoutService.connectVppPodsToVswitch(data);
    const vxTunnels = this.layoutService.connectBVIs(data);
    const bviLinks = this.layoutService.connectBVIsToVswitches(data);

    return [].concat(vppLinks, vxTunnels, bviLinks);
  }

  private createTopologyVswitch(vswitch: K8sPodModel): NodeData {
    const savedPosition = this.layoutService.getSavedPosition(vswitch.name, 'bd');
    const position = savedPosition ? savedPosition : {x: 0, y: 0};

    const node: NodeData = {
      id: vswitch.name,
      label: vswitch.name,
      x: position.x,
      y: position.y,
      fx: savedPosition ? savedPosition.x : null,
      fy: savedPosition ? savedPosition.y : null,
      nodeType: 'vswitch',
      IP: vswitch.podIp,
      namespace: vswitch.namespace,
      stroke: TopoColors.VSWITCH_STROKE
    };

    return node;
  }

  private createTopologyBVI(bvi: VppInterfaceModel, vswitch: NodeData): NodeData {
    const savedPosition = this.layoutService.getSavedPosition(vswitch.label + '-bvi', 'bd');
    const position = savedPosition ? savedPosition : {x: 0, y: 0};

    return {
      id: vswitch.label + '-bvi',
      x: position.x,
      y: position.y,
      fx: savedPosition ? savedPosition.x : null,
      fy: savedPosition ? savedPosition.y : null,
      stroke: TopoColors.BVI_STROKE,
      nodeType: 'bvi',
      IP: bvi.IPS
    };
  }

  private createTopologyVppPod(pod: K8sPodModel, vswitch: NodeData): NodeData {
    const savedPosition = this.layoutService.getSavedPosition(pod.name, 'bd');
    const position = savedPosition ? savedPosition : {x: 0, y: 0};

    const node: NodeData = {
      id: pod.name,
      label: pod.name,
      x: position.x,
      y: position.y,
      fx: savedPosition ? savedPosition.x : null,
      fy: savedPosition ? savedPosition.y : null,
      nodeType: 'vppPod',
      IP: pod.podIp,
      namespace: pod.namespace
    };

    return node;
  }

}
