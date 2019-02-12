import { Injectable } from '@angular/core';
import { NodeData } from '../../d3-topology/topology/topology-data/interfaces/node-data';
import { EdgeData } from '../../d3-topology/topology/topology-data/interfaces/edge-data';
import { ContivDataModel } from '../models/contiv-data-model';
import { CoreService } from './core.service';
import { TopoColors } from '../constants/topo-colors';
import { TopologyDataModel } from '../../d3-topology/topology/topology-data/models/topology-data-model';
import { Subject } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class LayoutService {

  public podCount = {};
  public layoutChangeSubject: Subject<boolean> = new Subject<boolean>();

  constructor(
    private coreService: CoreService
  ) { }

  public getBVIPosition(vswitch: NodeData): {x: number, y: number} {
    return {x: vswitch.x, y: vswitch.y};
  }

  public getSavedPosition(id: string, type: string): {x: number, y: number} {
    const data: {id: string, x: number, y: number}[] = JSON.parse(sessionStorage.getItem(type + '-topo'));

    if (!data) {
      return null;
    }

    const node = data.find(n => n.id === id);

    return node ? {x: node.x, y: node.y} : null;
  }

  public connectNodes(data: ContivDataModel): EdgeData[] {
    const master = data.getK8sMasterNode();

    return data.getK8sNodes().filter(n => n.name !== master.name).map(n => {
        const link: EdgeData = {
          id: this.coreService.generateRandomString(5),
          from: n.name,
          to: master.name,
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

    const pods = data.getVppPodsMapping().filter(m => !m.to.includes('coredns') && !m.to.includes('contiv-ui')).map(m => {
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

  public connectBVIsToVswitches(data: ContivDataModel): EdgeData[] {
    return data.contivData.map(d => {
      const link: EdgeData = {
        id: this.coreService.generateRandomString(5),
        from: d.vswitch.name,
        to: d.vswitch.name + '-bvi',
        type: 'node',
        fromType: 'node',
        toType: 'vxlan',
        width: '2px',
        clickable: false,
        isDashed: true
      };

      return link;
    });
  }

  public saveNodesPositions(topologyType: string, topology: TopologyDataModel) {
    const positions = topology.nodes.map(node => {
      return {
        id: node.id,
        x: node.x,
        y: node.y
      };
    });

    sessionStorage.setItem(topologyType, JSON.stringify(positions));
  }

  public clearNodesPositions() {
    sessionStorage.clear();
    this.layoutChangeSubject.next(true);
  }

}
