import { Injectable } from '@angular/core';

import { TopologyVizService } from './topology-viz.service';
import { LayerType } from 'src/app/shared/interfaces/layer-type';
import { TopologyService } from '../topology/topology.service';
import { NodeDataModel } from '../topology/topology-data/models/node-data-model';
import { EdgeDataModel } from '../topology/topology-data/models/edge-data-model';
import { K8sTopoNode } from '../topology/topology-data/models/nodes/k8s-topo-node';
import { VppTopoPod } from '../topology/topology-data/models/nodes/vpp-topo-pod';
import { VppTopoBvi } from '../topology/topology-data/models/nodes/vpp-topo-bvi';
import { VppTopoVswitch } from '../topology/topology-data/models/nodes/vpp-topo-vswitch';
import { TopologyType } from '../../shared/interfaces/topology-type';

import * as d3 from 'd3';

@Injectable({
  providedIn: 'root'
})
export class TopologyHighlightService {

  constructor(
    private topologyVizService: TopologyVizService,
    private topologyService: TopologyService
  ) { }

    /**
   * Clears selections of nodes and links from SVG
   */
  public clearSelections(): void {
    const svg = this.topologyVizService.getSvgObject();

    svg.selectAll('.selected-node')
      .classed('selected-node', false);

    svg.selectAll('.selected-bvi')
      .classed('selected-bvi', false);

    svg.selectAll('.selected-link')
      .classed('selected-link', false);
  }

  public clearNamespaceSelection() {
    const svg = this.topologyVizService.getSvgObject();

    svg.selectAll('.selected-namespace')
      .classed('selected-namespace', false);
  }

  /**
   * Sets opacity of links and nodes to desired number
   */
  public setTopologyOpacity(opacity: number) {
    const svg = this.topologyVizService.getSvgObject();

    svg.select('.links')
      .selectAll('.link')
      .attr('opacity', opacity);

    svg.select('.nodes')
      .selectAll('.node')
      .attr('opacity', opacity);
  }

  public clearHighlightedNode(nodeId: string) {
    this.topologyVizService.getSvgObject().select('#node' + nodeId)
      .classed('selected-node', false);
  }

    /**
   * Highlights node
   */
  public highlightNode(nodeId: string): void {
    this.topologyVizService.getSvgObject().select('#node' + nodeId)
      .classed('selected-node', true);
  }

  public highlightNamespace(namespace: string) {
    this.clearNamespaceSelection();

    const nodes = this.topologyService.getTopologyData().nodes;

    const nodesData = this.topologyVizService.getSvgObject()
      .selectAll('.node')
      .data(nodes, function (n: NodeDataModel) {
        return 'node' + n.id;
      })
      .filter(n => n.namespace === namespace)
      .classed('selected-namespace', true);
  }

  public highlightLink(linkId: string): void {
    this.topologyVizService.getSvgObject().select('#link' + linkId)
      .classed('selected-link', true);
  }

  public highlightLinkBetweenNodes(from: string, to: string) {
    const links = this.topologyService.getTopologyData().links;
    this.topologyVizService.getSvgObject()
      .selectAll('.link')
      .data(links, function (l: EdgeDataModel) {
        return l.id;
      })
      .filter(l => l.from === from && l.to === to || l.from === to && l.to === from)
      .classed('selected-link', true);
  }

  public highlightBVI(bviId: string): void {
    this.topologyVizService.getSvgObject().select('#bvi' + bviId)
      .classed('selected-bvi', true);
  }

  public highlightTunnelFromToNode(nodeId: string) {
    const links = this.topologyService.getTopologyData().links;
    this.topologyVizService.getSvgObject()
      .selectAll('.bezier')
      .data(links, function (l: EdgeDataModel) {
        return l.id;
      })
      .filter(l => l.from === nodeId || l.to === nodeId)
      .classed('selected-link', true);
  }

  public setLayer(layer: LayerType, topologyType: TopologyType) {
    this.clearSelections();
    this.clearNamespaceSelection();

    switch (topologyType) {
      case 'k8s':
        switch (layer) {
          case 'k8s-1':
            this.showK8sNodes();
            break;
          case 'k8s-2':
            this.showK8sNodesPods();
            break;
          case 'k8s-3':
            this.showK8sContivPods();
            break;
        }
        break;
      case 'vpp':
        switch (layer) {
          case 'vpp-1':
            this.showVppContivPods();
            break;
          case 'vpp-2':
            this.showApplicationPods();
            break;
          case 'vpp-3':
            this.showVxlanTunnels();
            break;
        }
        break;
      case 'bd':
        this.showVxlanTunnels();
        break;
    }
  }

  public showK8sNodes() {
    this.setTopologyOpacity(1);
    const nodes = this.topologyService.getTopologyData().nodes;
    const links = this.topologyService.getTopologyData().links;

    const nodesData = this.topologyVizService.getSvgObject()
      .selectAll('.node')
      .data(nodes, function (n: NodeDataModel) {
        return 'node' + n.id;
      });

    nodesData.filter(n => n instanceof K8sTopoNode)
      .classed('hidden', false);

    nodesData.filter(n => !(n instanceof K8sTopoNode))
      .classed('hidden', true);

    const linksData = this.topologyVizService.getSvgObject()
      .selectAll('.link')
      .data(links, function (l: EdgeDataModel) {
        return l.id;
      });

    linksData.filter(l => l.fromNodeObj instanceof K8sTopoNode && l.toNodeObj instanceof K8sTopoNode)
      .classed('hidden', false);

    linksData.filter(l => !(l.fromNodeObj instanceof K8sTopoNode) || !(l.toNodeObj instanceof K8sTopoNode))
      .classed('hidden', true);
  }

  public showK8sNodesPods() {
    this.setTopologyOpacity(1);
    this.topologyVizService.getSvgObject()
      .selectAll('.node')
      .classed('hidden', false);

    this.topologyVizService.getSvgObject()
      .selectAll('.link')
      .classed('hidden', false);
  }

  public showK8sContivPods() {
    this.showK8sNodesPods();
    this.setTopologyOpacity(0.2);

    const nodes = this.topologyService.getTopologyData().nodes;

    this.topologyVizService.getSvgObject()
      .selectAll('.node')
      .data(nodes, function (n: NodeDataModel) {
        return 'node' + n.id;
      })
      .filter(n => n.label.includes('contiv'))
      .attr('opacity', 1);
  }

  public showVppContivPods() {
    this.showK8sContivPods();
    this.setBviVisibility(false);
  }

  public showApplicationPods() {
    this.showK8sNodesPods();
    this.setBviVisibility(false);
    this.setTopologyOpacity(0.2);

    const nodes = this.topologyService.getTopologyData().nodes;

    const nodesData = this.topologyVizService.getSvgObject()
      .selectAll('.node')
      .data(nodes, function (n: NodeDataModel) {
        return 'node' + n.id;
      })
      .each(function (n) {
        if (n instanceof VppTopoPod && (n.label.startsWith('nginx') || n.label.startsWith('busybox'))) {
          d3.select(this).attr('opacity', 1);
        }
      });
  }

  public showVxlanTunnels() {
    this.showK8sNodesPods();
    this.setBviVisibility(true);
    this.showVppNodes();
  }

  private setBviVisibility(state: boolean) {
    const nodes = this.topologyService.getTopologyData().nodes;

    const nodesData = this.topologyVizService.getSvgObject()
      .selectAll('.node')
      .data(nodes, function (n: NodeDataModel) {
        return 'node' + n.id;
      })
      .each(function(node) {
        if (state) {
          if (node instanceof VppTopoPod && !node.label.includes('coredns') || node instanceof VppTopoVswitch) {
            d3.select(this).classed('hidden', false);
          } else {
            d3.select(this).classed('hidden', true);
          }
        }
      });

    const link = d3.selectAll('.link').classed('hidden', state);
    const bvis = d3.selectAll('.bvi').classed('hidden', !state);
    const vxlinks = d3.selectAll('.vxlink').classed('hidden', !state);

    if (state) {
      bvis.attr('opacity', 1);
      vxlinks.attr('opacity', 1);
    }
  }

  private showVppNodes() {
    const nodes = this.topologyService.getTopologyData().nodes;

    this.topologyVizService.getSvgObject()
      .selectAll('.node')
      .data(nodes, function (n: NodeDataModel) {
        return 'node' + n.id;
      })
      .each(function (n) {
        if (n instanceof VppTopoPod) {
          d3.select(this).attr('opacity', 1);
        } else if (n instanceof VppTopoVswitch) {
          d3.select(this).attr('opacity', 0.2);
        }
      });
  }
}
