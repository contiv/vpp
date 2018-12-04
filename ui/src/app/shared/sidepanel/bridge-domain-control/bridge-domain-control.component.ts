import { Component, OnInit, Input, OnChanges, SimpleChanges } from '@angular/core';
import { DataService } from '../../services/data.service';
import { ContivNodeDataModel } from '../../models/contiv-node-data-model';
import { VppInterfaceModel } from '../../models/vpp/vpp-interface-model';
import { Subscription } from 'rxjs';
import { VppBdModel } from '../../models/vpp/vpp-bd-model';

interface BdRow {
  node: string;
  bviIp: string;
  vrf: number;
  vni: number;
  podsCount: number;
  vxlansCount: number;
}

interface PodRow {
  name: string;
  iface: string;
  ip: string;
  node: string;
}

interface VxlanRow {
  srcNode: string;
  dstNode: string;
  name: string;
  srcIP: string;
  dstIP: string;
}

@Component({
  selector: 'app-bridge-domain-control',
  templateUrl: './bridge-domain-control.component.html',
  styleUrls: ['./bridge-domain-control.component.css']
})
export class BridgeDomainControlComponent implements OnInit, OnChanges {

  @Input() tableType: string;

  public bdSelect;
  public domains: ContivNodeDataModel[];
  public summaryObj: BdRow[];
  public podsObj: PodRow[];
  public tunnelsObj: VxlanRow[];
  public vxlans: VppInterfaceModel[];
  public bd: VppBdModel;

  public isSummary: boolean;
  public isPods: boolean;
  public isTunnels: boolean;

  private subscriptions: Subscription[];

  constructor(
    private dataService: DataService,
  ) { }

  ngOnInit() {
    this.subscriptions = [];
    this.summaryObj = [];
    this.podsObj = [];
    this.tunnelsObj = [];

    this.isSummary = false;
    this.isPods = false;
    this.isTunnels = false;

    this.subscriptions.push(
      this.dataService.isContivDataLoaded.subscribe(isLoaded => {
        if (isLoaded) {
          this.bd = this.dataService.contivData.contivData[0].bd[0];
          this.domains = this.dataService.contivData.contivData;
          this.summaryObj = this.domains.map(d => {
            const bvi = d.getBVI();
            const vxlans = d.getVxlans();
            const row: BdRow = {
              node: d.node.name,
              bviIp: bvi.IPS,
              vrf: bvi.vrf,
              vni: vxlans[0].vni,
              podsCount: d.getTapInterfaces().length,
              vxlansCount: vxlans.length
            };

            return row;
          });

          this.domains.forEach(d => {
            if (!d.node.isMaster()) {
              d.vppPods.forEach(pod => {
                const row: PodRow = {
                  name: pod.name,
                  iface: pod.tapInternalInterface,
                  ip: pod.podIp,
                  node: pod.node
                };

                this.podsObj.push(row);
              });
            }
          });

          this.domains.forEach(d => {
            d.getVxlans().forEach(vx => {
              const row: VxlanRow = {
                srcIP: vx.srcIP,
                srcNode: this.dataService.contivData.getNodeByIpamIp(vx.srcIP).name,
                dstIP: vx.dstIP,
                dstNode: this.dataService.contivData.getNodeByIpamIp(vx.dstIP).name,
                name: vx.name
              };

              this.tunnelsObj.push(row);
            });
          });
        }
      })
    );
  }

  ngOnChanges(changes: SimpleChanges) {
    if (!changes.tableType.firstChange) {
      switch (this.tableType) {
        case 'summary':
          this.isSummary = true;
          this.isPods = false;
          this.isTunnels = false;
          break;
        case 'pods':
          this.isSummary = false;
          this.isPods = true;
          this.isTunnels = false;
          break;
        case 'tunnels':
          this.isSummary = false;
          this.isPods = false;
          this.isTunnels = true;
          break;
      }
    }
  }
}
