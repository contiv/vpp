import { Component, OnInit, OnDestroy, ViewEncapsulation } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { Subscription } from 'rxjs';
import { DataService } from '../../services/data.service';
import { ContivNodeDataModel } from '../../models/contiv-node-data-model';
import { VswitchInterfaceList } from '../../interfaces/vswitch-interface-list';
import { ModalService } from '../../services/modal.service';
import { K8sPodModel } from '../../models/k8s/k8s-pod-model';
import { VppService } from '../../services/vpp.service';
import { AppConfig } from '../../../app-config';

@Component({
  selector: 'app-vswitch-diagram-control',
  templateUrl: './vswitch-diagram-control.component.html',
  styleUrls: ['./vswitch-diagram-control.component.css'],
})
export class VswitchDiagramControlComponent implements OnInit, OnDestroy {

  private subscriptions: Subscription[];
  private domain: ContivNodeDataModel;
  public vswitches: K8sPodModel[];
  public apis;
  public vswitchSelect: string;
  public apiList: {name: string, fn: any}[];

  constructor(
    private router: Router,
    private route: ActivatedRoute,
    private dataService: DataService,
    private modalService: ModalService,
    private vppService: VppService
  ) { }

  ngOnInit() {
    this.apiList = [
      {
        name: 'IPAM',
        fn: 'getIpamRaw'
      },
      {
        name: 'Interfaces',
        fn: 'getInterfacesRaw'
      },
      {
        name: 'VXLANs',
        fn: 'getVxlanInterfacesRaw'
      },
      {
        name: 'Taps',
        fn: 'getTapInterfacesRaw'
      },
      {
        name: 'Bridge Domains',
        fn: 'getbridgeDomainsRaw'
      },
      {
        name: 'Routes',
        fn: 'getRoutesRaw'
      },
      {
        name: 'NAT',
        fn: 'getNatRaw'
      },
      {
        name: 'Arps',
        fn: 'getArpsRaw'
      }
    ];

    this.subscriptions = [];
    this.subscriptions.push(
      this.route.params.subscribe(params => {
        this.subscriptions.push(
          this.dataService.isContivDataLoaded.subscribe(dataLoaded => {
            if (dataLoaded) {
              this.vswitchSelect = params.id;
              this.domain = this.dataService.contivData.getDomainByVswitchId(params.id);
              this.vswitches = this.dataService.contivData.getVswitches();
            }
          })
        );
      })
    );
  }

  public showNodeData() {
    this.modalService.showNodeDetail(this.domain.node.name);
  }

  public showInterfaces() {
    const data: VswitchInterfaceList = {
      title: this.domain.vswitch.name,
      interfaces: this.domain.interfaces
    };

    this.modalService.showVswitchInterfaces(data);
  }

  public selectVswitch(vswitchId: string) {
    this.router.navigate(['../', vswitchId], {relativeTo: this.route});
  }

  public showApi() {
    const restUrl = this.getRestUrl(this.domain.node.name);
    const fn = this.apiList.find(e => e.name === this.apis).fn;

    this.subscriptions.push(
      this.vppService[fn](restUrl).subscribe(output => this.modalService.showApiOutput(this.apis, JSON.stringify(output)))
    );
  }

  private getRestUrl(nodeId: string): string {
    let url: string;

    switch (nodeId) {
      case 'k8s-master':
        url = AppConfig.VPP_REST_MASTER_URL;
        break;
      case 'k8s-worker1':
        url = AppConfig.VPP_REST_WORKER1_URL;
        break;
      case 'k8s-worker2':
        url = AppConfig.VPP_REST_WORKER2_URL;
        break;
    }

    return url;
  }

  ngOnDestroy() {
    this.subscriptions.forEach(s => s.unsubscribe());
  }

}
