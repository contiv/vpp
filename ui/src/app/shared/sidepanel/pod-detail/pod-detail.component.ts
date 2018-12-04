import { Component, OnInit, OnDestroy } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { Subscription } from 'rxjs';
import { FormObject } from '../../interfaces/form-object';
import { DataService } from '../../services/data.service';
import { K8sPodModel } from '../../models/k8s/k8s-pod-model';
import { ContivNodeDataModel } from '../../models/contiv-node-data-model';
import { TopologyHighlightService } from '../../../d3-topology/topology-viz/topology-highlight.service';

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

  constructor(
    private route: ActivatedRoute,
    private dataService: DataService,
    private topologyHighlightService: TopologyHighlightService
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
              this.setFormData();
              this.topologyHighlightService.highlightNode(params.id);
            }
          })
        );
      })
    );
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
  }

}
