import { Component, OnInit, OnDestroy } from '@angular/core';
import { K8sPodModel } from '../../models/k8s/k8s-pod-model';
import { ContivNodeDataModel } from '../../models/contiv-node-data-model';
import { FormObject } from '../../interfaces/form-object';
import { Subscription } from 'rxjs';
import { ActivatedRoute } from '@angular/router';
import { DataService } from '../../services/data.service';
import { TopologyHighlightService } from '../../../d3-topology/topology-viz/topology-highlight.service';
import { SidepanelService } from '../sidepanel.service';
import { ModalService } from '../../services/modal.service';

@Component({
  selector: 'app-vpp-pod-detail',
  templateUrl: './vpp-pod-detail.component.html',
  styleUrls: ['./vpp-pod-detail.component.css']
})
export class VppPodDetailComponent implements OnInit, OnDestroy {

  public pod: K8sPodModel;
  public domain: ContivNodeDataModel;
  public formData: FormObject[];

  private iface: string;
  private subscriptions: Subscription[];

  constructor(
    private route: ActivatedRoute,
    private dataService: DataService,
    private topologyHighlightService: TopologyHighlightService,
    private sidepanelService: SidepanelService,
    private modalService: ModalService
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
              this.pod = this.domain.getPodById(params.id);

              const iface = this.domain.getTapByInternalName(this.pod.tapInternalInterface);
              this.iface = iface ? iface.internalName : '';
              this.setFormData();
              this.sidepanelService.openSidepanel();
              this.topologyHighlightService.highlightNode(params.id);
            }
          })
        );
      })
    );
  }

  public showContainers() {
    this.modalService.showContainers(this.pod);
  }

  private setFormData() {
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
        value: this.pod.podIp
      },
      {
        label: 'Interface',
        value: this.iface
      }
    ];
  }

  ngOnDestroy() {
    this.subscriptions.forEach(s => s.unsubscribe());
  }

}
