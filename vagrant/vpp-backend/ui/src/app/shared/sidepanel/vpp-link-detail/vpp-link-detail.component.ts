import { Component, OnInit, OnDestroy } from '@angular/core';
import { K8sPodModel } from '../../models/k8s/k8s-pod-model';
import { ContivNodeDataModel } from '../../models/contiv-node-data-model';
import { FormObject } from '../../interfaces/form-object';
import { Subscription } from 'rxjs';
import { ActivatedRoute } from '@angular/router';
import { DataService } from '../../services/data.service';
import { TopologyHighlightService } from '../../../d3-topology/topology-viz/topology-highlight.service';
import { SidepanelService } from '../sidepanel.service';
import { VppInterfaceModel } from '../../models/vpp/vpp-interface-model';

@Component({
  selector: 'app-vpp-link-detail',
  templateUrl: './vpp-link-detail.component.html',
  styleUrls: ['./vpp-link-detail.component.css']
})
export class VppLinkDetailComponent implements OnInit, OnDestroy {

  public pod: K8sPodModel;
  public domain: ContivNodeDataModel;
  public ifaceData: FormObject[];
  public podData: FormObject[];
  public iface: VppInterfaceModel;

  private subscriptions: Subscription[];

  constructor(
    private route: ActivatedRoute,
    private dataService: DataService,
    private topologyHighlightService: TopologyHighlightService,
    private sidepanelService: SidepanelService
  ) { }

  ngOnInit() {
    this.subscriptions = [];
    this.ifaceData = [];

    this.subscriptions.push(
      this.route.params.subscribe(params => {

        this.subscriptions.push(
          this.dataService.isContivDataLoaded.subscribe(isLoaded => {
            if (isLoaded) {
              this.domain = this.dataService.contivData.getDomainByVswitchId(params.to);
              if (!this.domain) {
                this.domain = this.dataService.contivData.getDomainByVswitchId(params.from);
              }

              this.pod = this.domain.getPodById(params.from);
              if (!this.pod) {
                this.pod = this.domain.getPodById(params.to);
              }

              this.iface = this.domain.getInterfaceByName(this.pod.tapInterface);
              this.setFormData();
              this.sidepanelService.openSidepanel();
              this.topologyHighlightService.highlightLinkBetweenNodes(params.from, params.to);
            }
          })
        );
      })
    );
  }

  private setFormData() {
    this.ifaceData = [
      {
        label: 'Interface',
        value: this.iface.internalName
      },
      {
        label: 'TAP IP',
        value: this.iface.IPS
      },
      {
        label: 'MAC',
        value: this.iface.mac
      },
      {
        label: 'VRF',
        value: this.iface.vrf.toString()
      }
    ];

    this.podData = [
      {
        label: 'Host IP',
        value: this.pod.hostIp
      },
      {
        label: 'Pod IP',
        value: this.pod.podIp
      }
    ];
  }

  ngOnDestroy() {
    this.subscriptions.forEach(s => s.unsubscribe());
  }


}
