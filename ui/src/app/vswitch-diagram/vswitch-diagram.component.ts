import { Component, OnInit, OnDestroy } from '@angular/core';
import { Subscription } from 'rxjs';
import { DataService } from '../shared/services/data.service';
import { ActivatedRoute } from '@angular/router';
import { ContivNodeDataModel } from '../shared/models/contiv-node-data-model';
import { VppInterfaceModel } from '../shared/models/vpp/vpp-interface-model';
import { VppService } from '../shared/services/vpp.service';

@Component({
  selector: 'app-vswitch-diagram',
  templateUrl: './vswitch-diagram.component.html',
  styleUrls: ['./vswitch-diagram.component.css']
})
export class VswitchDiagramComponent implements OnInit, OnDestroy {

  public isSidepanelOpen: boolean;
  public isSidepanelOpened: boolean;
  public vswitchId: string;
  public domain: ContivNodeDataModel;
  public taps: VppInterfaceModel[];
  public bvi: VppInterfaceModel;
  public vxlans: VppInterfaceModel[];
  public nic: VppInterfaceModel;
  public version: string;

  private subscriptions: Subscription[];
  private dataSubscription: Subscription;
  private versionSubscription: Subscription;

  constructor(
    private route: ActivatedRoute,
    private dataService: DataService,
    private vppService: VppService
  ) { }

  ngOnInit() {
    this.init();
    this.subscriptions.push(
      this.route.params.subscribe(params => {
        // is ID change
        if (this.vswitchId !== params.id) {
          if (this.dataSubscription) {
            this.dataSubscription.unsubscribe();
          }

          if (this.versionSubscription) {
            this.versionSubscription.unsubscribe();
          }
        }
        this.vswitchId = params.id;


        this.dataSubscription = this.dataService.isContivDataLoaded.subscribe(dataLoaded => {
          if (dataLoaded) {
            this.domain = this.dataService.contivData.getDomainByVswitchId(this.vswitchId);
            this.taps = this.domain.getTapInterfaces();
            this.bvi = this.domain.getBVI();
            this.vxlans = this.domain.getVxlans();
            this.nic = this.domain.getGigInterface();

            this.versionSubscription = this.vppService.getVersion(this.domain.node.ip).subscribe(output => this.version = output);
          }
        });
      })
    );
  }

  private init() {
    this.subscriptions = [];
    this.isSidepanelOpen = true;
  }

  public toggleSidepanel(state: boolean) {
    this.isSidepanelOpen = state;
  }

  ngOnDestroy() {
    this.subscriptions.forEach(s => s.unsubscribe());

    if (this.dataSubscription) {
      this.dataSubscription.unsubscribe();
    }

    if (this.versionSubscription) {
      this.versionSubscription.unsubscribe();
    }
  }

}
