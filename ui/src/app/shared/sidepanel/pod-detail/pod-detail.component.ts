import { Component, OnInit, OnDestroy } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { Subscription } from 'rxjs';
import { FormObject } from '../../interfaces/form-object';
import { DataService } from '../../services/data.service';
import { K8sPodModel } from '../../models/k8s/k8s-pod-model';
import { ContivNodeDataModel } from '../../models/contiv-node-data-model';
import { TopologyHighlightService } from '../../../d3-topology/topology-viz/topology-highlight.service';
import { ModalService } from '../../services/modal.service';
import { SidepanelService } from '../sidepanel.service';

@Component({
  selector: 'app-pod-detail',
  templateUrl: './pod-detail.component.html',
  styleUrls: ['./pod-detail.component.css']
})
export class PodDetailComponent implements OnInit, OnDestroy {

  public pod: K8sPodModel;
  public domain: ContivNodeDataModel;
  public formData: FormObject[];

  private subscriptions: Subscription[];
  private dataSubscription: Subscription;
  private nodeId: string;

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
    setTimeout(() => this.sidepanelService.openSidepanel(), 0);

    this.subscriptions.push(
      this.route.params.subscribe(params => {
        // is ID change
        if (this.nodeId !== params.id && this.dataSubscription) {
          this.dataSubscription.unsubscribe();
        }

        this.nodeId = params.id;

        this.dataSubscription = this.dataService.isContivDataLoaded.subscribe(isLoaded => {
          if (isLoaded) {
            this.domain = this.dataService.contivData.getDomainByPodId(this.nodeId);
            this.pod = this.domain.getPodById(this.nodeId);
            this.setFormData();
            this.topologyHighlightService.highlightNode(this.nodeId);
          }
        });
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
