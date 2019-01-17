import { Component, OnInit, OnDestroy } from '@angular/core';
import { IpCidrMap } from '../../interfaces/ip-cidr-map';
import { ModalService } from '../../services/modal.service';
import { Subscription } from 'rxjs';

@Component({
  selector: 'app-ip-mapping-modal',
  templateUrl: './ip-mapping-modal.component.html',
  styleUrls: ['./ip-mapping-modal.component.css']
})
export class IpMappingModalComponent implements OnInit, OnDestroy {

  public nodeLabel: string;
  public ipsMapping: IpCidrMap[];
  public isModalOpened: boolean;

  private subscriptions: Subscription[];

  constructor(
    private modalService: ModalService
  ) { }

  ngOnInit() {
    this.subscriptions = [];
    this.ipsMapping = [];
    this.isModalOpened = false;

    this.subscriptions.push(
      this.modalService.ipMappingModalSubject.subscribe(obj => {
        this.ipsMapping = obj.data;
        this.nodeLabel = obj.title;
        this.isModalOpened = true;
      })
    );
  }

  ngOnDestroy() {
    this.subscriptions.forEach(s => s.unsubscribe());
  }

}
