import { Component, OnInit, OnDestroy } from '@angular/core';
import { K8sPodModel } from '../../models/k8s/k8s-pod-model';
import { ContivNodeDataModel } from '../../models/contiv-node-data-model';
import { FormObject } from '../../interfaces/form-object';
import { Subscription } from 'rxjs';
import { ActivatedRoute } from '@angular/router';
import { DataService } from '../../services/data.service';
import { TopologyHighlightService } from '../../../d3-topology/topology-viz/topology-highlight.service';
import { ModalService } from '../../services/modal.service';
import { VswitchInterfaceList } from '../../interfaces/vswitch-interface-list';
import { SidepanelService } from '../sidepanel.service';

@Component({
  selector: 'app-vswitch-detail',
  templateUrl: './vswitch-detail.component.html',
  styleUrls: ['./vswitch-detail.component.css']
})
export class VswitchDetailComponent implements OnInit, OnDestroy {

  public pod: K8sPodModel;
  public domain: ContivNodeDataModel;
  public formData: FormObject[];

  private subscriptions: Subscription[];

  constructor(
    private route: ActivatedRoute,
    private dataService: DataService,
    private topologyHighlightService: TopologyHighlightService,
    private modalService: ModalService,
    private sidepanelService: SidepanelService
  ) { }


  ngOnInit() {
    this.subscriptions = [];
    this.formData = [];

    this.subscriptions.push(
      this.route.params.subscribe(params => {

        this.subscriptions.push(
          this.dataService.isContivDataLoaded.subscribe(isLoaded => {
            if (isLoaded) {
              this.domain = this.dataService.contivData.getDomainByPodId(params.id);
              this.pod = this.domain.vswitch;
              this.setFormData();
              this.sidepanelService.openSidepanel();
              this.topologyHighlightService.highlightNode(params.id);
            }
          })
        );
      })
    );
  }

  public showInterfaces() {
    const data: VswitchInterfaceList = {
      title: this.domain.vswitch.name,
      interfaces: this.domain.interfaces
    };

    this.modalService.showVswitchInterfaces(data);
  }

  private setFormData() {
    const gig = this.domain.getGigInterface();

    this.formData = [
      {
        label: 'Namespace',
        value: this.pod.namespace
      },
      {
        label: 'Host IP',
        value: this.pod.hostIp
      },
      {
        label: 'Pod IP',
        value: gig.getIP()
      }
    ];
  }

  ngOnDestroy() {
    this.subscriptions.forEach(s => s.unsubscribe());
  }


}
