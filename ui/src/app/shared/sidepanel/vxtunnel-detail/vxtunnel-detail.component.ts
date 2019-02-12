import { Component, OnInit, OnDestroy } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { Subscription } from 'rxjs';
import { ContivNodeDataModel } from '../../models/contiv-node-data-model';
import { FormObject } from '../../interfaces/form-object';
import { DataService } from '../../services/data.service';
import { TopologyHighlightService } from '../../../d3-topology/topology-viz/topology-highlight.service';
import { SidepanelService } from '../sidepanel.service';
import { VppInterfaceModel } from '../../models/vpp/vpp-interface-model';

@Component({
  selector: 'app-vxtunnel-detail',
  templateUrl: './vxtunnel-detail.component.html',
  styleUrls: ['./vxtunnel-detail.component.css']
})
export class VxtunnelDetailComponent implements OnInit, OnDestroy {

  public domainFrom: ContivNodeDataModel;
  public domainTo: ContivNodeDataModel;
  public vxlanData1: FormObject[];
  public vxlanData2: FormObject[];
  public vxlans: VppInterfaceModel[];

  private subscriptions: Subscription[];
  private dataSubscription: Subscription;
  private fromId: string;
  private toId: string;

  constructor(
    private route: ActivatedRoute,
    private dataService: DataService,
    private topologyHighlightService: TopologyHighlightService,
    private sidepanelService: SidepanelService
  ) { }

  ngOnInit() {
    this.subscriptions = [];
    this.vxlanData1 = [];
    this.vxlanData2 = [];

    this.subscriptions.push(
      this.route.params.subscribe(params => {
        // is ID change
        if (this.fromId !== params.from || this.toId !== params.to) {
          if (this.dataSubscription) {
            this.dataSubscription.unsubscribe();
          }
        }

        this.dataSubscription = this.dataService.isContivDataLoaded.subscribe(isLoaded => {
          if (isLoaded) {
            this.domainFrom = this.dataService.contivData.getDomainByVswitchId(params.from);
            this.domainTo = this.dataService.contivData.getDomainByVswitchId(params.to);

            const fromIp = this.domainFrom.getIpamNodeIp();
            const toIp = this.domainTo.getIpamNodeIp();

            this.vxlans = this.dataService.contivData.getVxlansByIps(fromIp, toIp);

            this.setFormData();
            this.sidepanelService.openSidepanel();
            this.topologyHighlightService.highlightLinkBetweenNodes(params.from, params.to);
          }
        });
      })
    );
  }

  private setFormData() {
    const srcNode1 = this.dataService.contivData.getNodeByIpamIp(this.vxlans[0].srcIP).name;
    const dstNode1 = this.dataService.contivData.getNodeByIpamIp(this.vxlans[0].dstIP).name;

    const srcNode2 = this.dataService.contivData.getNodeByIpamIp(this.vxlans[1].srcIP).name;
    const dstNode2 = this.dataService.contivData.getNodeByIpamIp(this.vxlans[1].dstIP).name;

    this.vxlanData1 = [
      {
        label: 'Source IP',
        value: this.vxlans[0].srcIP
      },
      {
        label: 'Destination IP',
        value: this.vxlans[0].dstIP
      },
      {
        label: 'VNI',
        value: this.vxlans[0].vni.toString()
      },
      {
        label: 'Direction',
        value: srcNode1 + ' -> ' + dstNode1
      }
    ];

    this.vxlanData2 = [
      {
        label: 'Source IP',
        value: this.vxlans[1].srcIP
      },
      {
        label: 'Destination IP',
        value: this.vxlans[1].dstIP
      },
      {
        label: 'VNI',
        value: this.vxlans[0].vni.toString()
      },
      {
        label: 'Direction',
        value: srcNode2 + ' -> ' + dstNode2
      }
    ];
  }

  ngOnDestroy() {
    this.subscriptions.forEach(s => s.unsubscribe());

    if (this.dataSubscription) {
      this.dataSubscription.unsubscribe();
    }
  }

}
