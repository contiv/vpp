import { Component, OnInit, OnDestroy } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { K8sNodeModel } from 'src/app/shared/models/k8s/k8s-node-model';
import { Subscription } from 'rxjs';
import { TopologyHighlightService } from 'src/app/d3-topology/topology-viz/topology-highlight.service';
import { DataService } from '../../services/data.service';

@Component({
  selector: 'app-nodes',
  templateUrl: './nodes.component.html',
  styleUrls: ['./nodes.component.css']
})
export class NodesComponent implements OnInit, OnDestroy {

  public nodes: K8sNodeModel[];
  private nodesSubscription: Subscription;

  constructor(
    private router: Router,
    private route: ActivatedRoute,
    private dataService: DataService,
    private topologyHighlighService: TopologyHighlightService
  ) { }

  ngOnInit() {
    this.nodes = [];
    this.nodesSubscription = this.dataService.isContivDataLoaded.subscribe(isLoaded => {
      if (isLoaded) {
        this.nodes = this.dataService.contivData.getK8sNodes();
      }
    });
  }

  public highlighNode(nodeId: string) {
    this.topologyHighlighService.highlightNode(nodeId);
  }

  public showDetail(nodeId: string) {
    this.topologyHighlighService.highlightNode(nodeId);
    this.router.navigate(['../node', nodeId], {relativeTo: this.route});
  }

  public clearHighlight() {
    this.topologyHighlighService.clearSelections();
  }

  ngOnDestroy() {
    if (this.nodesSubscription) {
      this.nodesSubscription.unsubscribe();
    }
  }

}
