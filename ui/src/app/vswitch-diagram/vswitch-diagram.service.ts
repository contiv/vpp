import { Injectable } from '@angular/core';
import { CoreService } from '../shared/services/core.service';
import { K8sPodModel } from '../shared/models/k8s/k8s-pod-model';
import { VppInterfaceModel } from '../shared/models/vpp/vpp-interface-model';
import { NodeData } from '../d3-topology/topology/topology-data/interfaces/node-data';
import { EdgeData } from '../d3-topology/topology/topology-data/interfaces/edge-data';
import { TopologyType } from '../shared/interfaces/topology-type';
import { ContivNodeDataModel } from '../shared/models/contiv-node-data-model';

@Injectable({
  providedIn: 'root'
})
export class VswitchDiagramService {

  private podCount = 0;
  private tapCount = 0;

  constructor(
    private coreService: CoreService
  ) { }

  public getTopologyData(data: ContivNodeDataModel): {nodes: NodeData[], links: EdgeData[], type: TopologyType} {
    this.podCount = 0;
    this.tapCount = 0;

    let nodeData: NodeData[] = [];
    let linkData: EdgeData[] = [];

    const bvi = data.getBVI();
    const gig = data.getGigInterface();
    const vppTap = data.getVppTap();

    nodeData = nodeData.concat(this.createPodNodes(data.vppPods));
    nodeData = nodeData.concat(this.createTapNodes(data.getTapInterfaces()));
    nodeData.push(this.createBVI(bvi));
    nodeData.push(this.createGigPort(gig));
    nodeData.push(this.createVppTap(vppTap));

    linkData = this.createPodTapLinks(data);
    linkData.push(this.createGigBviLink(bvi.name, gig.name));

    return {nodes: nodeData, links: linkData, type: 'vswitch'};
  }

  private createPodTapLinks(data: ContivNodeDataModel): EdgeData[] {
    const links: EdgeData[] = [];

    data.vppPods.forEach(pod => {
      const tap = data.interfaces.find(iface => iface.name === pod.tapInterface);
      links.push({
        id: this.coreService.generateRandomString(5),
        from: pod.name,
        to: tap.name,
        type: 'node',
        fromType: 'node',
        toType: 'node'
      });
    });

    return links;
  }

  private createGigBviLink(bviId: string, gigId: string): EdgeData {
    const link: EdgeData = {
      id: this.coreService.generateRandomString(5),
      from: bviId,
      to: gigId,
      type: 'node',
      fromType: 'node',
      toType: 'node'
    };

    return link;
  }

  private createPodNodes(vppPods: K8sPodModel[]): NodeData[] {
    return vppPods.map(pod => {
      const position = this.getPodPosition(pod);
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
    });
  }

  private createTapNodes(taps: VppInterfaceModel[]): NodeData[] {
    return taps.map(tap => {
      const position = this.getTapPosition(tap);
      const node: NodeData = {
        id: tap.name,
        label: tap.internalName,
        x: position.x,
        y: position.y,
        nodeType: 'iface',
        IP: tap.IPS
      };

      return node;
    });
  }

  private createGigPort(iface: VppInterfaceModel): NodeData {
    const position = this.getGigPosition(iface);
    return {
      id: iface.name,
      label: iface.name,
      x: position.x,
      y: position.y,
      nodeType: 'iface',
      IP: iface.IPS
    };
  }

  private createVppTap(iface: VppInterfaceModel): NodeData {
    const position = this.getVppTapPosition(iface);
    return {
      id: iface.name,
      label: iface.name,
      x: position.x,
      y: position.y,
      nodeType: 'iface',
      IP: iface.IPS
    };
  }

  private createBVI(iface: VppInterfaceModel): NodeData {
    const position = this.getBVIPosition(iface);
    return {
      id: iface.name,
      label: iface.name,
      x: position.x,
      y: position.y,
      nodeType: 'iface',
      IP: iface.IPS
    };
  }

  private getVppTapPosition(iface: VppInterfaceModel): {x: number, y: number} {
    const offsetX = 100;
    const offsetY = 100;

    return {x: this.podCount * offsetX * 4, y: 4 * offsetY};
  }

  private getBVIPosition(iface: VppInterfaceModel): {x: number, y: number} {
    const offsetX = 100;
    const offsetY = 100;

    const x = ((this.podCount * offsetX * 3) + offsetX * 3) / 2;

    return {x: x, y: 5 * offsetY};
  }

  private getGigPosition(iface: VppInterfaceModel): {x: number, y: number} {
    const offsetX = 100;
    const offsetY = 100;

    const x = ((this.podCount * offsetX * 3) + offsetX * 3) / 2;

    return {x: x, y: 6 * offsetY};
  }

  private getPodPosition(pod: K8sPodModel): {x: number, y: number} {
    const offsetX = 100;
    const offsetY = 100;

    this.podCount++;

    return {x: this.podCount * offsetX * 3, y: 2 * offsetY};
  }

  private getTapPosition(tap: VppInterfaceModel): {x: number, y: number} {
    const offsetX = 100;
    const offsetY = 100;

    this.tapCount++;

    return {x: this.tapCount * offsetX * 3, y: 3 * offsetY};
  }

  private connectPod(pod: K8sPodModel): EdgeData {
    const edgeData: EdgeData = {
      id: this.coreService.generateRandomString(5),
      from: pod.name,
      to: pod.node,
      type: 'node',
      fromType: 'node',
      toType: 'node'
    };

    return edgeData;
  }
}
