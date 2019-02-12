import { Component, OnInit, OnDestroy } from '@angular/core';
import { Subscription } from 'rxjs';
import { ActivatedRoute} from '@angular/router';
import { FormObject } from '../../interfaces/form-object';
import { DataService } from '../../services/data.service';
import { ContivNodeDataModel } from '../../models/contiv-node-data-model';
import { TopologyHighlightService } from '../../../d3-topology/topology-viz/topology-highlight.service';
import { IpCidrMap } from '../../interfaces/ip-cidr-map';
import { ModalService } from '../../services/modal.service';
import { SidepanelService } from '../sidepanel.service';

@Component({
  selector: 'app-node-detail',
  templateUrl: './node-detail.component.html',
  styleUrls: ['./node-detail.component.css']
})
export class NodeDetailComponent implements OnInit, OnDestroy {

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
            this.domain = this.dataService.contivData.getDomainByNodeId(this.nodeId);
            this.setFormData();
            this.topologyHighlightService.highlightNode(this.nodeId);
          }
        });
      })
    );
  }

  public showIPAM() {
    const bviIp = this.domain.getBVI().getIP();
    const tap0Ip = this.domain.getInterfaceByName('tap0').getIP();

    const ipsMapping: IpCidrMap[] = [
      {
        label: 'VPP IP',
        ip: this.domain.ipam.nodeIP,
        cidr: this.domain.ipam.nodeInterconnectCIDR
      },
      {
        label: 'BVI IP',
        ip: bviIp,
        cidr: this.domain.ipam.vxlanCIDR
      },
      {
        label: 'VPP 2 HOST',
        ip: tap0Ip,
        cidr: this.domain.ipam.vppHostSubnetCIDR
      }
    ];

    this.domain.vppPods.forEach(pod => {
      const podNetwork: IpCidrMap = {
        label: 'POD IP (' + pod.name + ')',
        ip: pod.podIp,
        cidr: this.domain.ipam.podNetwork
      };

      ipsMapping.push(podNetwork);
    });

    this.modalService.setIpMappingData(this.domain.node.name, ipsMapping);
  }

  private setFormData() {
    this.formData = [
      {
        label: 'Node ID',
        value: this.domain.ipam.nodeId.toString()
      },
      {
        label: 'Internal IP',
        value: this.domain.node.ip
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
