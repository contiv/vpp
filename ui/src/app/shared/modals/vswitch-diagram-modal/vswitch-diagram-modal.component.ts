import { Component, OnInit, OnDestroy } from '@angular/core';
import { Subscription } from 'rxjs';
import { ModalService } from '../../services/modal.service';
import { DataService } from '../../services/data.service';
import { TopologyService } from '../../../d3-topology/topology/topology.service';
import { NodeClickEvent } from '../../../d3-topology/topology/interfaces/events/node-click-event';
import { LinkClickEvent } from '../../../d3-topology/topology/interfaces/events/link-click-event';
import { SvgTransform } from '../../../d3-topology/topology/interfaces/svg-transform';
import { NodeData } from '../../../d3-topology/topology/topology-data/interfaces/node-data';
import { EdgeData } from '../../../d3-topology/topology/topology-data/interfaces/edge-data';
import { TopologyDataModel } from '../../../d3-topology/topology/topology-data/models/topology-data-model';
import { VppService } from '../../services/vpp.service';
import { TopologyType } from '../../interfaces/topology-type';

@Component({
  selector: 'app-vswitch-diagram-modal',
  templateUrl: './vswitch-diagram-modal.component.html',
  styleUrls: ['./vswitch-diagram-modal.component.css']
})
export class VswitchDiagramModalComponent implements OnInit, OnDestroy {

  private subscriptions: Subscription[];
  public isModalOpened: boolean;
  public vswitchLabel: string;

  public topoData: {nodes: NodeData[], links: EdgeData[], type: TopologyType};

  constructor(
    private modalService: ModalService,
    private dataService: DataService,
    private vppService: VppService,
    private topologyService: TopologyService,
  ) { }

  ngOnInit() {
    this.subscriptions = [];
    this.isModalOpened = false;

    // this.subscriptions.push(
    //   this.modalService.vswitchModalSubject.subscribe(vswitch => {
    //     this.isModalOpened = true;
    //     this.vswitchLabel = vswitch;

    //     this.subscriptions.push(this.dataService.isContivDataLoaded.subscribe(dataLoaded => {
    //       if (dataLoaded) {
    //         const domain = this.dataService.contivData.getDomainByVswitchId(vswitch);

    //         const obj = {
    //           pods: domain.getPods(),
    //           interfaces: domain.interfaces
    //         };
    //         this.topoData = this.vppService.getTopologyData(obj);

    //         const topo: TopologyDataModel = new TopologyDataModel();
    //         topo.setData(this.topoData.nodes, this.topoData.links);
    //         this.topologyService.setTopologyData(topo);
    //       }
    //     }));
    //   })
    // );
  }

  public onNodeClicked(data: NodeClickEvent) {
  }

  public onNodeDblClicked(data: NodeClickEvent) {
  }

  public onBviClicked(data: NodeClickEvent) {
  }

  public onLinkClicked(data: LinkClickEvent) {
  }

  public onSvgClicked() {
  }

  public onTransform(transform: SvgTransform) {
  }

  public onRender() {
  }

  ngOnDestroy() {
    this.subscriptions.forEach(s => s.unsubscribe());
  }

}
