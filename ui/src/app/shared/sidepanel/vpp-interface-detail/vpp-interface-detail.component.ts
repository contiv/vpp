import { Component, OnInit, OnDestroy } from '@angular/core';
import { ContivNodeDataModel } from '../../models/contiv-node-data-model';
import { FormObject } from '../../interfaces/form-object';
import { VppInterfaceModel } from '../../models/vpp/vpp-interface-model';
import { Subscription } from 'rxjs';
import { ActivatedRoute } from '@angular/router';
import { DataService } from '../../services/data.service';
import { TopologyHighlightService } from '../../../d3-topology/topology-viz/topology-highlight.service';
import { SidepanelService } from '../sidepanel.service';

@Component({
  selector: 'app-vpp-interface-detail',
  templateUrl: './vpp-interface-detail.component.html',
  styleUrls: ['./vpp-interface-detail.component.css']
})
export class VppInterfaceDetailComponent implements OnInit, OnDestroy {

  public domain: ContivNodeDataModel;
  public ifaceData: FormObject[];
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
          this.route.parent.params.subscribe(parentParams => {
            this.subscriptions.push(
              this.dataService.isContivDataLoaded.subscribe(isLoaded => {
                if (isLoaded) {
                  this.domain = this.dataService.contivData.getDomainByVswitchId(parentParams.id);
                  this.iface = this.domain.getInterfaceByName(params.id);

                  this.setFormData();
                  this.sidepanelService.openSidepanel();
                  this.topologyHighlightService.highlightNode(params.id);
                }
              })
            );
          })
        );
      })
    );
  }

  private setFormData() {
    this.ifaceData = [
      {
        label: 'IP',
        value: this.iface.IPS
      },
      {
        label: 'MAC',
        value: this.iface.mac
      }
    ];
  }

  ngOnDestroy() {
    this.subscriptions.forEach(s => s.unsubscribe());
  }

}
