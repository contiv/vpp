import { Component, OnInit, OnDestroy } from '@angular/core';
import { Subscription } from 'rxjs';
import { ModalService } from '../../services/modal.service';
import { ContivNodeDataModel } from '../../models/contiv-node-data-model';
import { IpCidrMap } from '../../interfaces/ip-cidr-map';
import { FormObject } from '../../interfaces/form-object';

@Component({
  selector: 'app-node-detail-modal',
  templateUrl: './node-detail-modal.component.html',
  styleUrls: ['./node-detail-modal.component.css']
})
export class NodeDetailModalComponent implements OnInit, OnDestroy {

  private subscriptions: Subscription[];
  private domain: ContivNodeDataModel;
  public formData: FormObject[];
  public nodeLabel: string;
  public ipsMapping: IpCidrMap[];
  public isModalOpened: boolean;

  constructor(
    private modalService: ModalService
  ) { }

  ngOnInit() {
    this.subscriptions = [];
    this.formData = [];
    this.ipsMapping = [];
    this.isModalOpened = false;

    this.subscriptions.push(
      this.modalService.nodeDetailSubject.subscribe(domain => {
        this.domain = domain;
        this.nodeLabel = domain.node.name;
        this.setFormData();
        this.setIPAM();
        this.isModalOpened = true;
      })
    );
  }

  public setIPAM() {
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

    this.ipsMapping = ipsMapping;
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
