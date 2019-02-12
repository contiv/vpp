import { Component, OnInit, OnDestroy } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { Subscription } from 'rxjs';
import { DataService } from '../../services/data.service';
import { ContivNodeDataModel } from '../../models/contiv-node-data-model';
import { FormObject } from '../../interfaces/form-object';
import { VppInterfaceModel } from '../../models/vpp/vpp-interface-model';
import { TopologyHighlightService } from '../../../d3-topology/topology-viz/topology-highlight.service';
import { SidepanelService } from '../sidepanel.service';

@Component({
  selector: 'app-bvi-detail',
  templateUrl: './bvi-detail.component.html',
  styleUrls: ['./bvi-detail.component.css']
})
export class BviDetailComponent implements OnInit, OnDestroy {

  public domain: ContivNodeDataModel;
  public bviData: FormObject[];
  public vxlansData: FormObject[][];
  public bvi: VppInterfaceModel;
  public vxlans: VppInterfaceModel[];

  private subscriptions: Subscription[];
  private dataSubscription: Subscription;
  private bviId: string;

  constructor(
    private route: ActivatedRoute,
    private dataService: DataService,
    private topologyHighlightService: TopologyHighlightService,
    private sidepanelService: SidepanelService
  ) { }

  ngOnInit() {
    this.subscriptions = [];
    this.bviData = [];
    this.vxlansData = [];
    setTimeout(() => this.sidepanelService.openSidepanel(), 0);

    this.subscriptions.push(
      this.route.params.subscribe(params => {
        // is ID change
        if (this.bviId !== params.id && this.dataSubscription) {
          this.dataSubscription.unsubscribe();
        }

        this.bviId = params.id;

        this.dataSubscription = this.dataService.isContivDataLoaded.subscribe(isLoaded => {
          if (isLoaded) {
            this.domain = this.dataService.contivData.getDomainByVswitchId(this.bviId);
            this.bvi = this.domain.getBVI();
            this.vxlans = this.domain.getVxlans();
            this.setFormData();
            this.topologyHighlightService.highlightBVI(this.bviId);
            this.topologyHighlightService.highlightTunnelFromToNode(this.bviId);
          }
        });
      })
    );
  }

  private setFormData() {
    this.bviData = [
      {
        label: 'BVI IP',
        value: this.bvi.IPS
      },
      {
        label: 'VRF',
        value: this.bvi.vrf.toString()
      }
    ];

    this.vxlansData = this.vxlans.map(vx => {
      const srcNode = this.dataService.contivData.getNodeByIpamIp(vx.srcIP).name;
      const dstNode = this.dataService.contivData.getNodeByIpamIp(vx.dstIP).name;

      return [
        {
          label: 'Source IP',
          value: vx.srcIP
        },
        {
          label: 'Destination IP',
          value: vx.dstIP
        },
        {
          label: 'VNI',
          value: vx.vni.toString()
        },
        {
          label: 'Direction',
          value: srcNode + ' -> ' + dstNode
        }
      ];
    });
  }

  ngOnDestroy() {
    this.subscriptions.forEach(s => s.unsubscribe());

    if (this.dataSubscription) {
      this.dataSubscription.unsubscribe();
    }
  }

}
