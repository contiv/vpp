import { Component, OnInit, OnDestroy } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { K8sPodModel } from 'src/app/shared/models/k8s/k8s-pod-model';
import { Subscription } from 'rxjs';
import { TopologyHighlightService } from 'src/app/d3-topology/topology-viz/topology-highlight.service';
import { DataService } from '../../services/data.service';

@Component({
  selector: 'app-pods',
  templateUrl: './pods.component.html',
  styleUrls: ['./pods.component.css']
})
export class PodsComponent implements OnInit, OnDestroy {

  public pods: K8sPodModel[];
  public options;
  private podsSubcription: Subscription;

  constructor(
    private router: Router,
    private route: ActivatedRoute,
    private dataService: DataService,
    private topologyHighlightService: TopologyHighlightService
  ) { }

  ngOnInit() {
    this.pods = [];
    this.podsSubcription = this.dataService.isContivDataLoaded.subscribe(isLoaded => {
      if (isLoaded) {
        this.pods = this.dataService.contivData.getAllPods();
      }
    });
  }

  public showDetail(pod: K8sPodModel) {
    let type = '';

    if (pod.isVppPod()) {
      type = 'vppPod';
    } else if (pod.isVswitch()) {
      type = 'vswitch';
    } else {
      type = 'pod';
    }

    this.topologyHighlightService.highlightNode(pod.name);

    const relativeUrlSegment = this.router.url.includes('kubernetes') ? '../' : '../contiv/';
    this.router.navigate([relativeUrlSegment + type, pod.name], {relativeTo: this.route});
  }

  public highlighNode(podId: string) {
    this.topologyHighlightService.highlightNode(podId);
  }

  public clearHighlight() {
    this.topologyHighlightService.clearSelections();
  }

  ngOnDestroy() {
    if (this.podsSubcription) {
      this.podsSubcription.unsubscribe();
    }
  }

}
