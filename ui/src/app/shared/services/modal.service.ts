import { Injectable } from '@angular/core';
import { Subject } from 'rxjs';
import { IpCidrMap } from '../interfaces/ip-cidr-map';
import { VswitchInterfaceList } from '../interfaces/vswitch-interface-list';
import { ContivNodeDataModel } from '../models/contiv-node-data-model';

@Injectable({
  providedIn: 'root'
})
export class ModalService {

  public ipMappingModalSubject: Subject<{title: string, data: IpCidrMap[]}> = new Subject<{title: string, data: IpCidrMap[]}>();
  public vswitchModalSubject: Subject<string> = new Subject<string>();
  public vswitchInterfacesModalSubject: Subject<VswitchInterfaceList> = new Subject<VswitchInterfaceList>();
  public nodeDetailSubject: Subject<ContivNodeDataModel> = new Subject<ContivNodeDataModel>();
  public outputSubject: Subject<{api: string, response: string}> = new Subject<{api: string, response: string}>();

  constructor() { }

  public setIpMappingData(title: string, data: IpCidrMap[]) {
    this.ipMappingModalSubject.next({title: title, data: data});
  }

  public showVswitchDiagram(vswitchId: string) {
    this.vswitchModalSubject.next(vswitchId);
  }

  public showVswitchInterfaces(data: VswitchInterfaceList) {
    this.vswitchInterfacesModalSubject.next(data);
  }

  public showNodeDetail(domain: ContivNodeDataModel) {
    this.nodeDetailSubject.next(domain);
  }

  public showApiOutput(api: string, response: string) {
    this.outputSubject.next({api: api, response: response});
  }

}
