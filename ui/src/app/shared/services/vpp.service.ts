import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { map } from 'rxjs/operators';
import { Observable } from 'rxjs';
import { CoreService } from './core.service';
import { AppConfig } from 'src/app/app-config';
import { VppIpamModel } from '../models/vpp/vpp-ipam-model';
import { VppInterfaceModel } from '../models/vpp/vpp-interface-model';
import { VppRouteModel } from '../models/vpp/vpp-route-model';
import { VppArpModel } from '../models/vpp/vpp-arp-model';
import { VppInterfaceVxlanModel } from '../models/vpp/vpp-interface-vxlan-model';
import { VppBdModel } from '../models/vpp/vpp-bd-model';
import { VppInterfaceTapModel } from '../models/vpp/vpp-interface-tap-model';

@Injectable({
  providedIn: 'root'
})
export class VppService {

  constructor(
    private http: HttpClient,
    private coreService: CoreService
  ) { }

  public getIPAM(restUrl: string): Observable<VppIpamModel> {
    return this.http.get(restUrl + AppConfig.API_V1_CONTIV + 'ipam').pipe(
      map(res => {
        return this.coreService.extractObjectData(res, VppIpamModel);
      })
    );
  }

  public getIpamRaw(restUrl: string) {
    return this.http.get(restUrl + AppConfig.API_V1_CONTIV + 'ipam');
  }

  public getRoutes(restUrl: string): Observable<VppRouteModel[]> {
    return this.http.get(restUrl + AppConfig.API_V1_VPP + 'routes').pipe(
      map(res => {
        return this.coreService.extractListData(res as Array<any>, VppRouteModel);
      })
    );
  }

  public getRoutesRaw(restUrl: string) {
    return this.http.get(restUrl + AppConfig.API_V1_VPP + 'routes');
  }

  public getArps(restUrl: string): Observable<VppArpModel[]> {
    return this.http.get(restUrl + AppConfig.API_V1_VPP + 'arps').pipe(
      map(res => {
        return this.coreService.extractListData(res as Array<any>, VppArpModel);
      })
    );
  }

  public getArpsRaw(restUrl: string) {
    return this.http.get(restUrl + AppConfig.API_V1_VPP + 'arps');
  }

  public getInterfaces(restUrl: string): Observable<VppInterfaceModel[]> {
    return this.http.get(restUrl + AppConfig.API_V1_VPP + 'interfaces').pipe(
      map(res => {
        return this.coreService.extractObjectDataToArray(res, VppInterfaceModel);
      })
    );
  }

  public getInterfacesRaw(restUrl: string) {
    return this.http.get(restUrl + AppConfig.API_V1_VPP + 'interfaces');
  }

  public getVxlanInterfaces(restUrl: string): Observable<VppInterfaceVxlanModel[]> {
    return this.http.get(restUrl + AppConfig.API_V1_VPP + 'interfaces/vxlan').pipe(
      map(res => {
        return this.coreService.extractObjectDataToArray(res, VppInterfaceVxlanModel);
      })
    );
  }

  public getVxlanInterfacesRaw(restUrl: string) {
    return this.http.get(restUrl + AppConfig.API_V1_VPP + 'interfaces/vxlan');
  }

  public getTapInterfaces(restUrl: string): Observable<VppInterfaceTapModel[]> {
    return this.http.get(restUrl + AppConfig.API_V1_VPP + 'interfaces/tap').pipe(
      map(res => {
        return this.coreService.extractObjectDataToArray(res, VppInterfaceTapModel);
      })
    );
  }

  public getTapInterfacesRaw(restUrl: string) {
    return this.http.get(restUrl + AppConfig.API_V1_VPP + 'interfaces/tap');
  }

  public getBridgeDomains(restUrl: string): Observable<VppBdModel[]> {
    return this.http.get(restUrl + AppConfig.API_V1_VPP + 'bd').pipe(
      map(res => {
        return this.coreService.extractObjectDataToArray(res, VppBdModel);
      })
    );
  }

  public getbridgeDomainsRaw(restUrl: string) {
    return this.http.get(restUrl + AppConfig.API_V1_VPP + 'bd');
  }

  public getNatRaw(restUrl: string) {
    return this.http.get(restUrl + AppConfig.API_V1_VPP + 'nat');
  }

  public getVersion(restUrl: string) {
    const headers = new HttpHeaders({
      'Content-Type':  'application/json',
    });

    const body = {'vppclicommand': 'show version'};

    return this.http.post(restUrl + 'vpp/command', body, {headers, responseType: 'text'}).pipe(

    );
  }
}
