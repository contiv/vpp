import { Component, OnInit, OnDestroy } from '@angular/core';
import { NodeData } from '../d3-topology/topology/topology-data/interfaces/node-data';
import { EdgeData } from '../d3-topology/topology/topology-data/interfaces/edge-data';
import { Subscription } from 'rxjs';
import { DataService } from '../shared/services/data.service';
import { LayerType } from '../shared/interfaces/layer-type';
import { K8sTopologyService } from './k8s-topology.service';
import { TopologyService } from '../d3-topology/topology/topology.service';
import { SidepanelService } from '../shared/sidepanel/sidepanel.service';
import { TopologyHighlightService } from '../d3-topology/topology-viz/topology-highlight.service';
import { ModalService } from '../shared/services/modal.service';
import { NodeClickEvent } from '../d3-topology/topology/interfaces/events/node-click-event';
import { LinkClickEvent } from '../d3-topology/topology/interfaces/events/link-click-event';
import { SvgTransform } from '../d3-topology/topology/interfaces/svg-transform';
import { TopologyDataModel } from '../d3-topology/topology/topology-data/models/topology-data-model';
import { TopologyType } from '../shared/interfaces/topology-type';
import { K8sNamespaceModel } from '../shared/models/k8s/k8s-namespace-model';

@Component({
  selector: 'app-kubernetes',
  templateUrl: './kubernetes.component.html',
  styleUrls: ['./kubernetes.component.css']
})
export class KubernetesComponent implements OnInit, OnDestroy {

  public isSidepanelOpen: boolean;
  public activeLayers: boolean[];
  public highlightedNamespace: boolean[];
  public layerTitle: string;
  public layerType: LayerType;
  public topoData: {nodes: NodeData[], links: EdgeData[], type: TopologyType};
  public namespaces: K8sNamespaceModel[];

  private subscriptions: Subscription[];

  constructor(
    private k8sTopologyService: K8sTopologyService,
    private dataService: DataService,
    private topologyService: TopologyService,
    private sidepanelService: SidepanelService,
    private topologyHighlightService: TopologyHighlightService,
    private modalService: ModalService
  ) { }

  ngOnInit() {
    this.init();
    this.subscriptions.push(this.dataService.isContivDataLoaded.subscribe(dataLoaded => {
      if (dataLoaded) {
        this.topoData = this.k8sTopologyService.getTopologyData(this.dataService.contivData);
        this.namespaces = this.dataService.contivData.getNamespaces();

        const topo: TopologyDataModel = new TopologyDataModel();
        topo.setData(this.topoData.nodes, this.topoData.links);
        this.topologyService.setTopologyData(topo);
      }
    }));
  }

  public setK8sNodesLayer() {
    this.activeLayers = [true, false, false];
    this.layerTitle = 'K8s Nodes';
    this.layerType = 'k8s-1';
    this.topologyHighlightService.setLayer(this.layerType, this.topoData.type);
  }

  public setK8sNodesPodsLayer() {
    this.activeLayers = [false, true, false];
    this.layerTitle = 'K8s Nodes + Pods';
    this.layerType = 'k8s-2';
    this.topologyHighlightService.setLayer(this.layerType, this.topoData.type);
  }

  public setContivPodsLayer() {
    this.activeLayers = [false, false, true];
    this.layerTitle = 'Contiv Pods';
    this.layerType = 'k8s-3';
    this.topologyHighlightService.setLayer(this.layerType, this.topoData.type);
  }

  public toggleSidepanel(state: boolean) {
    this.isSidepanelOpen = state;
  }

  public onNodeClicked(data: NodeClickEvent) {
    this.topologyHighlightService.clearSelections();
    this.sidepanelService.setSpNodeItem(data.node, this.topoData.type);
  }

  public onNodeDblClicked(data: NodeClickEvent) {
    this.modalService.showVswitchDiagram(data.node.id);
  }

  public onBviClicked(data: NodeClickEvent) {
  }

  public onLinkClicked(data: LinkClickEvent) {
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

  private init() {
    this.subscriptions = [];
    this.topoData = {nodes: [], links: [], type: 'k8s'};
    this.namespaces = [];
    this.layerTitle = 'K8s Nodes';
    this.layerType = 'k8s-1';
    this.isSidepanelOpen = true;
    this.activeLayers = [true, false, false];
    this.highlightedNamespace = [false, false, false];
  }

  ngOnDestroy() {
    this.subscriptions.forEach(s => s.unsubscribe());
  }

}
