import { Component, OnInit, OnDestroy } from '@angular/core';
import { Subscription } from 'rxjs';
import { ModalService } from '../../services/modal.service';
import { VppInterfaceModel } from '../../models/vpp/vpp-interface-model';

interface InterfacesData {
  name: string;
  IP: string;
  MAC: string;
  srcIP: string;
  dstIP: string;
}

@Component({
  selector: 'app-vswitch-interfaces-modal',
  templateUrl: './vswitch-interfaces-modal.component.html',
  styleUrls: ['./vswitch-interfaces-modal.component.css']
})
export class VswitchInterfacesModalComponent implements OnInit, OnDestroy {

  public vswitchLabel: string;
  public interfaces: InterfacesData[];
  public tunnels: InterfacesData[];
  public isModalOpened: boolean;

  private subscriptions: Subscription[];

  constructor(
    private modalService: ModalService
  ) { }

  ngOnInit() {
    this.subscriptions = [];
    this.isModalOpened = false;
    this.interfaces = [];
    this.tunnels = [];

    this.subscriptions.push(
      this.modalService.vswitchInterfacesModalSubject.subscribe(obj => {
        this.interfaces = obj.interfaces.filter(i => !i.isVxtunnel()).map(i => {
          let name: string;

          if (i.isTap() || !i.name) {
            name = i.internalName;
          } else {
            name = i.name;
          }

          const iface: InterfacesData = {
            name: name,
            IP: i.IPS,
            MAC: i.mac,
            srcIP: i.srcIP,
            dstIP: i.dstIP
          };

          return iface;
        });

        this.tunnels = obj.interfaces.filter(i => i.isVxtunnel()).map(i => {
          const iface: InterfacesData = {
            name: i.name,
            IP: i.IPS,
            MAC: i.mac,
            srcIP: i.srcIP,
            dstIP: i.dstIP
          };

          return iface;
        });

        this.vswitchLabel = obj.title;
        this.isModalOpened = true;
      })
    );
  }

  ngOnDestroy() {
    this.subscriptions.forEach(s => s.unsubscribe());
  }

}
