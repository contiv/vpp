import { Component, OnInit, OnDestroy } from '@angular/core';
import { Subscription } from 'rxjs';
import { ActivatedRoute} from '@angular/router';
import { FormObject } from '../../interfaces/form-object';
import { DataService } from '../../services/data.service';
import { ContivNodeDataModel } from '../../models/contiv-node-data-model';
import { TopologyHighlightService } from '../../../d3-topology/topology-viz/topology-highlight.service';
import { IpCidrMap } from '../../interfaces/ip-cidr-map';
import { VppInterfaceModel } from '../../models/vpp/vpp-interface-model';
import { ModalService } from '../../services/modal.service';

@Component({
  selector: 'app-node-detail',
  templateUrl: './node-detail.component.html',
  styleUrls: ['./node-detail.component.css']
})
export class NodeDetailComponent implements OnInit, OnDestroy {

  public domain: ContivNodeDataModel;
  public formData: FormObject[];

  private subscriptions: Subscription[];

  constructor(
    private route: ActivatedRoute,
    private dataService: DataService,
    private topologyHighlightService: TopologyHighlightService,
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
              this.domain = this.dataService.contivData.getDomainByNodeId(params.id);
              this.setFormData();
              this.topologyHighlightService.highlightNode(params.id);
            }
          })
        );
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

    this.domain.vppPods.forEach(pod => {
      const podIfIp: IpCidrMap = {
        label: 'POD IF IP (' + pod.name + ')',
        ip: pod.getVppIp(),
        cidr: this.domain.ipam.podIfIPCIDR
      };

      ipsMapping.push(podIfIp);
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
  }

}
