import { Injectable } from '@angular/core';
import { K8sNodeModel } from '../models/k8s/k8s-node-model';
import { K8sPodModel } from '../models/k8s/k8s-pod-model';
import { NodeData } from '../../d3-topology/topology/topology-data/interfaces/node-data';
import { EdgeData } from '../../d3-topology/topology/topology-data/interfaces/edge-data';
import { ContivDataModel } from '../models/contiv-data-model';
import { CoreService } from './core.service';
import { TopoColors } from '../constants/topo-colors';

@Injectable({
  providedIn: 'root'
})
export class LayoutService {

  public podCount = {};

  constructor(
    private coreService: CoreService
  ) { }

  public getNodePosition(node: K8sNodeModel): {x: number, y: number} {
    const offsetX = 100;
    const offsetY = 100;

    switch (node.name) {
      case 'k8s-master':
        return {x: 7 * offsetX, y: 3 * offsetY};
      case 'k8s-worker1':
        return {x: 4 * offsetX, y: 6 * offsetY};
      case 'k8s-worker2':
        return {x: 10 * offsetX, y: 6 * offsetY};
      default:
        return {x: 100, y: 150};
    }
  }

  public getPodPosition(pod: K8sPodModel): {x: number, y: number} {
    const offsetX = 110;
    const offsetY = 100;

    if (this.podCount[pod.node]) {
      this.podCount[pod.node]++;
    } else {
      this.podCount[pod.node] = 1;
    }

    switch (pod.node) {
      case 'k8s-master':
        return this.coreService.getPointOnEllipse(550, 250, (this.podCount[pod.node] - 2.8) * -25, {x: 700, y: 300});
      case 'k8s-worker1':
        return {x: ((this.podCount[pod.node]) * 2) * offsetX, y: 7.2 * offsetY};
      case 'k8s-worker2':
        return {x: (6 + (this.podCount[pod.node]) * 2) * offsetX, y: 8 * offsetY};
      default:
        return {x: 100, y: 150};
    }
  }

  public getVppPodPosition(pod: K8sPodModel, vswitchData: NodeData, isBd?: boolean): {x: number, y: number} {
    const offsetX = 110;
    const offsetY = 100;

    const w1Offset = isBd ? 2 : 0;
    const w2Offset = isBd ? 2 : 0;

    if (this.podCount[pod.node]) {
      this.podCount[pod.node]++;
    } else {
      this.podCount[pod.node] = 1;
    }

    switch (pod.node) {
      case 'k8s-master':
        return {x: ((1 + this.podCount[pod.node]) * 2) * offsetX, y: vswitchData.y - offsetY * 1.5};
      case 'k8s-worker1':
        return {x: (w1Offset + (this.podCount[pod.node]) * 2) * offsetX, y: 7.2 * offsetY};
      case 'k8s-worker2':
        return {x: (6 + w2Offset + (this.podCount[pod.node]) * 2) * offsetX, y: 8 * offsetY};
      default:
        return {x: 100, y: 150};
    }
  }

  public getBVIPosition(vswitch: NodeData): {x: number, y: number} {
    return {x: vswitch.x, y: vswitch.y};
  }

  public getVswitchPosition(vswitch: K8sPodModel): {x: number, y: number} {
    const offsetX = 100;
    const offsetY = 100;

    switch (vswitch.node) {
      case 'k8s-master':
        return {x: 5 * offsetX, y: 3 * offsetY};
      case 'k8s-worker1':
        return {x: 6 * offsetX, y: 6.5 * offsetY};
      case 'k8s-worker2':
        return {x: 12 * offsetX, y: 6.5 * offsetY};
    }
  }

  public connectNodes(data: ContivDataModel): EdgeData[] {
    const master = 'k8s-master';

    return data.getK8sNodes().filter(n => n.name !== master).map(n => {
        const link: EdgeData = {
          id: this.coreService.generateRandomString(5),
          from: n.name,
          to: master,
          color: TopoColors.NODE_LINK,
          width: '3px',
          type: 'node',
          fromType: 'node',
          toType: 'node'
        };

        return link;
    });
  }

  public connectVswitchesToHost(data: ContivDataModel): EdgeData[] {
    return data.getVswitches().map(pod => {
      const link: EdgeData = {
        id: this.coreService.generateRandomString(5),
        from: pod.name,
        to: pod.node,
        type: 'node',
        fromType: 'node',
        toType: 'node'
      };

      return link;
    });
  }

  public connectPodsToHost(data: ContivDataModel): EdgeData[] {
    return data.getK8sPods().map(pod => {
      const link: EdgeData = {
        id: this.coreService.generateRandomString(5),
        from: pod.name,
        to: pod.node,
        type: 'node',
        fromType: 'node',
        toType: 'node'
      };

      return link;
    });
  }

  public connectVppPodsToVswitch(data: ContivDataModel): EdgeData[] {
    let links: EdgeData[] = [];

    data.contivData.forEach(d => {
      links = links.concat(d.vppPods.map(pod => {
        const link: EdgeData = {
          id: this.coreService.generateRandomString(5),
          from: pod.name,
          to: d.vswitch.name,
          type: 'node',
          fromType: 'node',
          toType: 'node',
          width: '3px'
        };

        return link;
      }));
    });

    return links;
  }

  public connectBVIs(data: ContivDataModel): EdgeData[] {
    const vxlans = data.getVxlanMapping().map(m => {
      const link: EdgeData = {
        id: this.coreService.generateRandomString(5),
        from: m.from + '-bvi',
        to: m.to + '-bvi',
        color: TopoColors.BVI_LINK,
        width: '3px',
        type: 'vxlan',
        fromType: 'vxlan',
        toType: 'vxlan'
      };

      return link;
    });

    const pods = data.getVppPodsMapping().filter(m => !m.to.includes('coredns')).map(m => {
      const link: EdgeData = {
        id: this.coreService.generateRandomString(5),
        from: m.from + '-bvi',
        to: m.to,
        color: TopoColors.BVI_LINK,
        width: '3px',
        type: 'vxlan',
        fromType: 'vxlan',
        toType: 'node'
      };

      return link;
    });

    return vxlans.concat(pods);
  }
}
