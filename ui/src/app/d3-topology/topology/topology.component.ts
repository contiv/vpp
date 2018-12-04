import { Component, OnInit, OnDestroy, OnChanges, SimpleChanges, Input } from '@angular/core';
import { TopologyService } from './topology.service';
import { TopologyDataModel } from './topology-data/models/topology-data-model';
import { NodeClickEvent } from './interfaces/events/node-click-event';
import { LinkClickEvent } from './interfaces/events/link-click-event';
import { SvgTransform } from './interfaces/svg-transform';
import { NodeData } from './topology-data/interfaces/node-data';
import { EdgeData } from './topology-data/interfaces/edge-data';
import { SidepanelService } from 'src/app/shared/sidepanel/sidepanel.service';
import { TopologyHighlightService } from '../topology-viz/topology-highlight.service';
import { LayerType } from 'src/app/shared/interfaces/layer-type';
import { ModalService } from '../../shared/services/modal.service';
import { EdgeDataModel } from './topology-data/models/edge-data-model';
import { VppTopoPod } from './topology-data/models/nodes/vpp-topo-pod';
import { VppTopoVswitch } from './topology-data/models/nodes/vpp-topo-vswitch';
import { VppTopoBvi } from './topology-data/models/nodes/vpp-topo-bvi';
import { TopologyType } from '../../shared/interfaces/topology-type';

@Component({
  selector: 'app-topology',
  templateUrl: './topology.component.html',
  styleUrls: ['./topology.component.css']
})
export class TopologyComponent implements OnInit, OnDestroy, OnChanges {

  @Input() data: {nodes: NodeData[], links: EdgeData[], type: TopologyType};
  @Input() layer: LayerType;

  constructor(
    private topologyService: TopologyService,
    private sidepanelService: SidepanelService,
    private topologyHighlightService: TopologyHighlightService,
    private modalService: ModalService
  ) {
  }

  ngOnInit() {
    this.topologyService.setTopologyTransform({
      translate: [0, 0],
      scale: [1]
    });
  }

  ngOnChanges(changes: SimpleChanges) {
    if (changes.data) {
      const topo: TopologyDataModel = new TopologyDataModel();
      topo.setData(this.data.nodes, this.data.links);
      this.topologyService.setTopologyData(topo);
    }

    if (changes.layer && !changes.layer.firstChange) {
      this.topologyHighlightService.setLayer(this.layer, this.data.type);
    }
  }

  public onNodeClicked(data: NodeClickEvent) {
    this.topologyHighlightService.clearSelections();
    this.sidepanelService.setSpNodeItem(data.node, this.data.type);
  }

  public onNodeDblClicked(data: NodeClickEvent) {
    // this.modalService.showVswitchDiagram();
  }

  public onBviClicked(data: NodeClickEvent) {
    this.topologyHighlightService.clearSelections();
    this.sidepanelService.setSpNodeItem(data.node, this.data.type);
    this.topologyHighlightService.highlightBVI(data.node.id);
  }

  public onLinkClicked(data: LinkClickEvent) {
    let linkType: 'vppLink' | 'vxtunnel';
    if (this.isVppLink(data.link)) {
      linkType = 'vppLink';
    } else if (this.isVxtunnelLink(data.link)) {
      linkType = 'vxtunnel';
    }

    this.sidepanelService.setSpLinkItem(data.link, linkType, this.data.type);
  }

  public onSvgClicked() {
    this.topologyHighlightService.clearSelections();
    this.sidepanelService.setSpNodeItem(null, this.data.type);
  }

  public onTransform(transform: SvgTransform) {
  }

  public onRender() {
    this.topologyHighlightService.setLayer(this.layer, this.data.type);
  }

  private isVppLink(link: EdgeDataModel): boolean {
    return link.fromNodeObj instanceof VppTopoPod && link.toNodeObj instanceof VppTopoVswitch ||
      link.fromNodeObj instanceof VppTopoVswitch && link.toNodeObj instanceof VppTopoPod;
  }

  private isVxtunnelLink(link: EdgeDataModel): boolean {
    return link.fromNodeObj instanceof VppTopoBvi && link.toNodeObj instanceof VppTopoBvi;
  }

  ngOnDestroy() {

  }

}
