import { Component, OnInit, OnDestroy } from '@angular/core';
import { KubernetesService } from '../../services/kubernetes.service';
import { K8sServiceModel } from '../../models/k8s/k8s-service-model';
import { Subscription } from 'rxjs';
import { AppConfig } from 'src/app/app-config';
import { DataService } from '../../services/data.service';
import { K8sEndpointModel } from '../../models/k8s/k8s-endpoint-model';
import { TopologyHighlightService } from '../../../d3-topology/topology-viz/topology-highlight.service';
import { K8sTopologyService } from '../../../kubernetes/k8s-topology.service';
import { TopologyService } from '../../../d3-topology/topology/topology.service';
import { TopologyDataModel } from '../../../d3-topology/topology/topology-data/models/topology-data-model';
import { NodeClickEvent } from '../../../d3-topology/topology/interfaces/events/node-click-event';
import { NodeData } from '../../../d3-topology/topology/topology-data/interfaces/node-data';
import { EdgeData } from '../../../d3-topology/topology/topology-data/interfaces/edge-data';
import { TopologyType } from '../../interfaces/topology-type';
import { SvgTransform } from '../../../d3-topology/topology/interfaces/svg-transform';
import { ModalService } from '../../services/modal.service';
import { VppService } from '../../services/vpp.service';
import { K8sNodeModel } from '../../models/k8s/k8s-node-model';

@Component({
  selector: 'app-services',
  templateUrl: './services.component.html',
  styleUrls: ['./services.component.css']
})
export class ServicesComponent implements OnInit, OnDestroy {

  public services: K8sServiceModel[];
  public endpoints: K8sEndpointModel[];
  public selectedService: K8sServiceModel;
  public selectedEndpoint: K8sEndpointModel;
  public shownEndpoints;
  public showAllServices: boolean;
  public shownTopology: boolean;
  public topoData: {nodes: NodeData[], links: EdgeData[], type: TopologyType};
  public svgTransform: SvgTransform;
  public k8sNodes: K8sNodeModel[];

  private subscriptions: Subscription[];

  constructor(
    private k8sService: KubernetesService,
    private dataService: DataService,
    private topologyHighlightService: TopologyHighlightService,
    private k8sTopologyService: K8sTopologyService,
    private topologyService: TopologyService,
    private modalService: ModalService,
    private vppService: VppService
  ) { }

  ngOnInit() {
    this.services = [];
    this.k8sNodes = [];
    this.subscriptions = [];
    this.shownTopology = false;
    this.showAllServices = false;

    this.subscriptions.push(
      this.dataService.isContivDataLoaded.subscribe(dataLoaded => {
        if (dataLoaded) {
          this.k8sNodes = this.dataService.contivData.getK8sNodes();

          this.subscriptions.push(
            this.k8sService.loadServices(AppConfig.K8S_REST_MASTER_URL).subscribe(services => {
              this.subscriptions.push(
                this.k8sService.loadEndpoints(AppConfig.K8S_REST_MASTER_URL).subscribe(endpoints => {
                  this.services = services;
                  this.endpoints = endpoints;
                })
              );
            })
          );
        } else {
          this.services = [];
          this.k8sNodes = [];
          this.resetService();
          this.selectedService = null;
        }
      })
    );
  }

  public selectService(i?: number) {
    if (i >= 0) {
      this.selectedService = this.services[i];
      this.selectedEndpoint = this.endpoints.find(e => e.name === this.selectedService.name);
      this.resetService();
    } else {
      this.selectedService = null;
      this.selectedEndpoint = null;
      this.shownEndpoints = false;
      this.showAllServices = true;
      this.shownTopology = false;
    }
  }

  public showTopology() {
    this.shownTopology = true;

    this.subscriptions.push(this.dataService.isContivDataLoaded.subscribe(dataLoaded => {
      if (dataLoaded) {
        this.topoData = this.k8sTopologyService.getTopologyData(this.dataService.contivData);

        const topo: TopologyDataModel = new TopologyDataModel();
        topo.setData(this.topoData.nodes, this.topoData.links);
        this.topologyService.setTopologyData(topo);
      }
    }));
  }

  public onNodeClicked(data: NodeClickEvent) {
  }

  public onSvgClicked() {
  }

  public onRender() {
    this.selectedEndpoint.subsets.forEach(s => {
      if (s.addresses) {
        s.addresses.forEach(a => this.topologyHighlightService.highlightNode(a.podName));
      }
    });
  }

  public highlightEndpoint(podId: string) {
    this.topologyHighlightService.clearSelections();
    this.topologyHighlightService.highlightNode(podId);
  }

  public hideTopology() {
    this.shownTopology = false;
  }

  public showVppState(nodeId: string) {
    const url = this.getRestUrl(nodeId);

    this.vppService.getNatRaw(url).subscribe(output => this.modalService.showApiOutput('NAT', JSON.stringify(output)));
  }

  public getHostIp(nodeId: string): string {
    const node = this.k8sNodes.find(n => n.name === nodeId);

    return node ? node.ip : '';
  }

  public resetPage() {
    this.resetService();
    this.selectedService = null;
    this.selectedEndpoint = null;
  }

  private resetService() {
    this.showAllServices = false;
    this.shownTopology = false;
    this.shownEndpoints = false;
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
