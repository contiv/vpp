import { Component, OnInit, OnDestroy } from '@angular/core';
import { Router } from '@angular/router';
import { NodeData } from '../d3-topology/topology/topology-data/interfaces/node-data';
import { EdgeData } from '../d3-topology/topology/topology-data/interfaces/edge-data';
import { Subscription } from 'rxjs';
import { LayerType } from '../shared/interfaces/layer-type';
import { DataService } from '../shared/services/data.service';
import { PodTopologyService } from './pod-topology.service';
import { TopologyService } from '../d3-topology/topology/topology.service';
import { SidepanelService } from '../shared/sidepanel/sidepanel.service';
import { TopologyHighlightService } from '../d3-topology/topology-viz/topology-highlight.service';
import { TopologyDataModel } from '../d3-topology/topology/topology-data/models/topology-data-model';
import { NodeClickEvent } from '../d3-topology/topology/interfaces/events/node-click-event';
import { LinkClickEvent } from '../d3-topology/topology/interfaces/events/link-click-event';
import { SvgTransform } from '../d3-topology/topology/interfaces/svg-transform';
import { EdgeDataModel } from '../d3-topology/topology/topology-data/models/edge-data-model';
import { VppTopoPod } from '../d3-topology/topology/topology-data/models/nodes/vpp-topo-pod';
import { VppTopoVswitch } from '../d3-topology/topology/topology-data/models/nodes/vpp-topo-vswitch';
import { VppTopoBvi } from '../d3-topology/topology/topology-data/models/nodes/vpp-topo-bvi';
import { TopologyType } from '../shared/interfaces/topology-type';
import { K8sNamespaceModel } from '../shared/models/k8s/k8s-namespace-model';

@Component({
  selector: 'app-pod-network',
  templateUrl: './pod-network.component.html',
  styleUrls: ['./pod-network.component.css']
})
export class PodNetworkComponent implements OnInit, OnDestroy {

  public isSidepanelOpen: boolean;
  public activeLayers: boolean[];
  public highlightedNamespace: boolean[];
  public layerTitle: string;
  public layerType: LayerType;
  public topoData: {nodes: NodeData[], links: EdgeData[], type: TopologyType};
  public namespaces: K8sNamespaceModel[];

  private subscriptions: Subscription[];

  constructor(
    private router: Router,
    private podTopologyService: PodTopologyService,
    private dataService: DataService,
    private topologyService: TopologyService,
    private sidepanelService: SidepanelService,
    private topologyHighlightService: TopologyHighlightService
  ) { }

  ngOnInit() {
    this.init();
    this.subscriptions.push(this.dataService.isContivDataLoaded.subscribe(dataLoaded => {
      if (dataLoaded) {
        this.topoData = this.podTopologyService.getTopologyData(this.dataService.contivData);
        this.namespaces = this.dataService.contivData.getNamespaces();

        const topo: TopologyDataModel = new TopologyDataModel();
        topo.setData(this.topoData.nodes, this.topoData.links);
        this.topologyService.setTopologyData(topo);
      }
    }));
  }

  public setContivPodsLayer() {
    this.activeLayers = [true, false, false];
    this.layerTitle = 'Contiv Pods';
    this.layerType = 'vpp-1';
    this.topologyHighlightService.setLayer(this.layerType, this.topoData.type);
    this.sidepanelService.openSidepanel();
  }

  public setAppPodsLayer() {
    this.activeLayers = [false, true, false];
    this.layerTitle = 'Application Pods';
    this.layerType = 'vpp-2';
    this.topologyHighlightService.setLayer(this.layerType, this.topoData.type);
    this.sidepanelService.openSidepanel();
  }

  public setVxlanLayer() {
    this.activeLayers = [false, false, true];
    this.layerTitle = 'VXLAN Tunnels';
    this.layerType = 'vpp-3';
    this.topologyHighlightService.setLayer(this.layerType, this.topoData.type);
    this.sidepanelService.closeSidepanel();
  }

  public toggleSidepanel(state: boolean) {
    this.isSidepanelOpen = state;
  }

  public onNodeClicked(data: NodeClickEvent) {
    this.topologyHighlightService.clearSelections();
    this.sidepanelService.setSpNodeItem(data.node, this.topoData.type);
  }

  public onNodeDblClicked(data: NodeClickEvent) {
    // this.modalService.showVswitchDiagram(data.node.id);
    this.router.navigate(['vswitch-diagram', data.node.id]);
  }

  public onBviClicked(data: NodeClickEvent) {
    this.topologyHighlightService.clearSelections();
    this.sidepanelService.setSpNodeItem(data.node, this.topoData.type);
    this.topologyHighlightService.highlightBVI(data.node.id);
  }

  public onLinkClicked(data: LinkClickEvent) {
    this.topologyHighlightService.clearSelections();

    let linkType: 'vppLink' | 'vxtunnel';
    if (this.isVppLink(data.link)) {
      linkType = 'vppLink';
    } else if (this.isVxtunnelLink(data.link)) {
      linkType = 'vxtunnel';
    }

    this.sidepanelService.setSpLinkItem(data.link, linkType, this.topoData.type);
  }

  public onSvgClicked() {
    this.topologyHighlightService.clearSelections();
    this.topologyHighlightService.clearNamespaceSelection();
    this.sidepanelService.setSpNodeItem(null, this.topoData.type);
    this.highlightedNamespace = [false, false, false];
  }

  public onTransform(transform: SvgTransform) {
  }

  public onRender() {
    this.topologyHighlightService.setLayer(this.layerType, this.topoData.type);
  }

  public highlightNamespace(namespace: string, i: number) {
    this.highlightedNamespace = [false, false, false];
    this.highlightedNamespace[i] = true;

    namespace ? this.topologyHighlightService.highlightNamespace(namespace) : this.topologyHighlightService.clearSelections();
  }

  private isVppLink(link: EdgeDataModel): boolean {
    return link.fromNodeObj instanceof VppTopoPod && link.toNodeObj instanceof VppTopoVswitch ||
      link.fromNodeObj instanceof VppTopoVswitch && link.toNodeObj instanceof VppTopoPod;
  }

  private isVxtunnelLink(link: EdgeDataModel): boolean {
    return link.fromNodeObj instanceof VppTopoBvi && link.toNodeObj instanceof VppTopoBvi;
  }

  private init() {
    this.subscriptions = [];
    this.topoData = {nodes: [], links: [], type: 'k8s'};
    this.namespaces = [];
    this.layerTitle = 'Contiv Pods';
    this.layerType = 'vpp-1';
    this.isSidepanelOpen = true;
    this.activeLayers = [true, false, false];
    this.highlightedNamespace = [false, false, false];
  }

  ngOnDestroy() {
    this.subscriptions.forEach(s => s.unsubscribe);
  }

}
