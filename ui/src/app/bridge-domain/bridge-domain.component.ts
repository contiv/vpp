import { Component, OnInit, OnDestroy } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { Subscription } from 'rxjs';
import { NodeData } from '../d3-topology/topology/topology-data/interfaces/node-data';
import { EdgeData } from '../d3-topology/topology/topology-data/interfaces/edge-data';
import { DataService } from '../shared/services/data.service';
import { TopologyService } from '../d3-topology/topology/topology.service';
import { SidepanelService } from '../shared/sidepanel/sidepanel.service';
import { TopologyHighlightService } from '../d3-topology/topology-viz/topology-highlight.service';
import { TopologyDataModel } from '../d3-topology/topology/topology-data/models/topology-data-model';
import { NodeClickEvent } from '../d3-topology/topology/interfaces/events/node-click-event';
import { LinkClickEvent } from '../d3-topology/topology/interfaces/events/link-click-event';
import { SvgTransform } from '../d3-topology/topology/interfaces/svg-transform';
import { EdgeDataModel } from '../d3-topology/topology/topology-data/models/edge-data-model';
import { VppTopoPod } from '../d3-topology/topology/topology-data/models/nodes/vpp-topo-pod';
import { VppTopoBvi } from '../d3-topology/topology/topology-data/models/nodes/vpp-topo-bvi';
import { TopologyType } from '../shared/interfaces/topology-type';
import { ContivNodeDataModel } from '../shared/models/contiv-node-data-model';
import { BridgeDomainService } from './bridge-domain.service';
import { LayoutService } from '../shared/services/layout.service';

@Component({
  selector: 'app-bridge-domain',
  templateUrl: './bridge-domain.component.html',
  styleUrls: ['./bridge-domain.component.css']
})
export class BridgeDomainComponent implements OnInit, OnDestroy {

  public isSidepanelOpen: boolean;
  public topoData: {nodes: NodeData[], links: EdgeData[], type: TopologyType};
  public domain: ContivNodeDataModel;
  public bdId: string;
  public showedTables: boolean[];
  public tableType: string;
  public svgTransform: SvgTransform;

  private subscriptions: Subscription[];

  constructor(
    private router: Router,
    private route: ActivatedRoute,
    private bdService: BridgeDomainService,
    private dataService: DataService,
    private topologyService: TopologyService,
    private sidepanelService: SidepanelService,
    private topologyHighlightService: TopologyHighlightService,
    private layoutService: LayoutService
  ) { }

  ngOnInit() {
    this.svgTransform = {
      translate: [-180, 0],
      scale: [1]
    };

    this.init();
    this.subscriptions.push(this.dataService.isContivDataLoaded.subscribe(dataLoaded => {
      if (dataLoaded) {
        this.topoData = this.bdService.getTopologyData(this.dataService.contivData);
        this.topoData.type = 'bd';
        this.domain = this.dataService.contivData.contivData[0];
        this.bdId = this.domain.bd[0].name;

        const topo: TopologyDataModel = new TopologyDataModel();
        topo.setData(this.topoData.nodes, this.topoData.links);
        this.topologyService.setTopologyData(topo);
      }
    }));
  }

  public toggleSidepanel(state: boolean) {
    this.isSidepanelOpen = state;
  }

  public onNodeClicked(data: NodeClickEvent) {
    this.topologyHighlightService.clearSelections();
    this.sidepanelService.setSpNodeItem(data.node, this.topoData.type);

    this.resetTables();
  }

  public onNodeDblClicked(data: NodeClickEvent) {
    this.router.navigate(['vswitch-diagram', data.node.id]);

    this.resetTables();
  }

  public onBviClicked(data: NodeClickEvent) {
    this.topologyHighlightService.clearSelections();
    this.sidepanelService.setSpNodeItem(data.node, this.topoData.type);
    this.topologyHighlightService.highlightBVI(data.node.id);
    this.topologyHighlightService.highlightTunnelFromToNode(data.node.id);

    this.resetTables();
  }

  public onLinkClicked(data: LinkClickEvent) {
    this.topologyHighlightService.clearSelections();

    let linkType: 'vppLink' | 'vxtunnel';
    if (this.isVppLink(data.link)) {
      linkType = 'vppLink';
    } else if (this.isVxtunnelLink(data.link)) {
      linkType = 'vxtunnel';
    }

    this.resetTables();

    this.sidepanelService.setSpLinkItem(data.link, linkType, this.topoData.type);
  }

  public onSvgClicked() {
    this.topologyHighlightService.clearSelections();
    this.sidepanelService.setSpNodeItem(null, this.topoData.type);
  }

  public onTransform(transform: SvgTransform) {
  }

  public onRender() {
    this.topologyHighlightService.setLayer('vpp-3', this.topoData.type);
  }

  public onPositionChange(topologyData: TopologyDataModel) {
    this.layoutService.saveNodesPositions('bd-topo', topologyData);
  }

  public showSummary() {
    this.onSvgClicked();

    if (this.showedTables[0]) {
      this.resetTables();
    } else {
      this.showedTables = [true, false, false];

      if (this.tableType === '') {
        this.tableType = 'summary';
      } else {
        this.tableType = '';
        setTimeout(() => this.tableType = 'summary', 300);
      }
    }
  }

  public showPods() {
    this.onSvgClicked();

    if (this.showedTables[1]) {
      this.resetTables();
    } else {
      this.showedTables = [false, true, false];

      if (this.tableType === '') {
        this.tableType = 'pods';
      } else {
        this.tableType = '';
        setTimeout(() => this.tableType = 'pods', 300);
      }
    }
  }

  public showTunnels() {
    this.onSvgClicked();

    if (this.showedTables[2]) {
      this.resetTables();
    } else {
      this.showedTables = [false, false, true];

      if (this.tableType === '') {
        this.tableType = 'tunnels';
      } else {
        this.tableType = '';
        setTimeout(() => this.tableType = 'tunnels', 300);
      }
    }
  }

  public showDetail(data: {nodeId: string, type: 'vppPod' | 'bvi' | 'vxtunnel', dstId: string}) {
    this.resetTables();
    this.isSidepanelOpen = true;

    switch (data.type) {
      case 'vppPod':
        this.topologyHighlightService.highlightNode(data.nodeId);
        this.router.navigate([data.type, data.nodeId], {relativeTo: this.route});
        break;
      case 'bvi':
        this.topologyHighlightService.highlightBVI(data.nodeId);
        this.topologyHighlightService.highlightTunnelFromToNode(data.nodeId);
        this.router.navigate([data.type, data.nodeId], {relativeTo: this.route});
        break;
      case 'vxtunnel':
        this.topologyHighlightService.highlightLinkBetweenNodes(data.nodeId, data.dstId);
        this.router.navigate([data.type, data.nodeId, data.dstId], {relativeTo: this.route});
        break;
    }
  }

  public resetTables() {
    this.showedTables = [false, false, false];
    this.tableType = '';
  }

  private isVppLink(link: EdgeDataModel): boolean {
    return link.fromNodeObj instanceof VppTopoPod && link.toNodeObj instanceof VppTopoBvi ||
      link.fromNodeObj instanceof VppTopoBvi && link.toNodeObj instanceof VppTopoPod;
  }

  private isVxtunnelLink(link: EdgeDataModel): boolean {
    return link.fromNodeObj instanceof VppTopoBvi && link.toNodeObj instanceof VppTopoBvi;
  }

  private init() {
    this.subscriptions = [];
    this.topoData = {nodes: [], links: [], type: 'k8s'};
    this.isSidepanelOpen = false;
    this.showedTables = [false, false, false];
    this.tableType = '';
  }

  ngOnDestroy() {
    this.subscriptions.forEach(s => s.unsubscribe);
  }
}
