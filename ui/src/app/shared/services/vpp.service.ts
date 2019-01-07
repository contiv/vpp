import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';
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

  public getIPAM(vswitchIp: string): Observable<VppIpamModel> {
    const params = new HttpParams().set('vswitch', vswitchIp);
    return this.http.get(AppConfig.VPP_REST_URL + AppConfig.API_V1_CONTIV + 'ipam', {params}).pipe(
      map(res => {
        return this.coreService.extractObjectData(res, VppIpamModel);
      })
    );
  }

  public getIpamRaw(vswitchIp: string) {
    const params = new HttpParams().set('vswitch', vswitchIp);
    return this.http.get(AppConfig.VPP_REST_URL + AppConfig.API_V1_CONTIV + 'ipam', {params});
  }

  public getRoutes(vswitchIp: string): Observable<VppRouteModel[]> {
    const params = new HttpParams().set('vswitch', vswitchIp);
    return this.http.get(AppConfig.VPP_REST_URL + AppConfig.API_V1_VPP + 'routes', {params}).pipe(
      map(res => {
        return this.coreService.extractListData(res as Array<any>, VppRouteModel);
      })
    );
  }

  public getRoutesRaw(vswitchIp: string) {
    const params = new HttpParams().set('vswitch', vswitchIp);
    return this.http.get(AppConfig.VPP_REST_URL + AppConfig.API_V1_VPP + 'routes', {params});
  }

  public getArps(vswitchIp: string): Observable<VppArpModel[]> {
    const params = new HttpParams().set('vswitch', vswitchIp);
    return this.http.get(AppConfig.VPP_REST_URL + AppConfig.API_V1_VPP + 'arps', {params}).pipe(
      map(res => {
        return this.coreService.extractListData(res as Array<any>, VppArpModel);
      })
    );
  }

  public getArpsRaw(vswitchIp: string) {
    const params = new HttpParams().set('vswitch', vswitchIp);
    return this.http.get(AppConfig.VPP_REST_URL + AppConfig.API_V1_VPP + 'arps', {params});
  }

  public getInterfaces(vswitchIp: string): Observable<VppInterfaceModel[]> {
    const params = new HttpParams().set('vswitch', vswitchIp);
    return this.http.get(AppConfig.VPP_REST_URL + AppConfig.API_V1_VPP + 'interfaces', {params}).pipe(
      map(res => {
        return this.coreService.extractObjectDataToArray(res, VppInterfaceModel);
      })
    );
  }

  public getInterfacesRaw(vswitchIp: string) {
    const params = new HttpParams().set('vswitch', vswitchIp);
    return this.http.get(AppConfig.VPP_REST_URL + AppConfig.API_V1_VPP + 'interfaces', {params});
  }

  public getVxlanInterfaces(vswitchIp: string): Observable<VppInterfaceVxlanModel[]> {
    const params = new HttpParams().set('vswitch', vswitchIp);
    return this.http.get(AppConfig.VPP_REST_URL + AppConfig.API_V1_VPP + 'interfaces/vxlan', {params}).pipe(
      map(res => {
        return this.coreService.extractObjectDataToArray(res, VppInterfaceVxlanModel);
      })
    );
  }

  public getVxlanInterfacesRaw(vswitchIp: string) {
    const params = new HttpParams().set('vswitch', vswitchIp);
    return this.http.get(AppConfig.VPP_REST_URL + AppConfig.API_V1_VPP + 'interfaces/vxlan', {params});
  }

  public getTapInterfaces(vswitchIp: string): Observable<VppInterfaceTapModel[]> {
    const params = new HttpParams().set('vswitch', vswitchIp);
    return this.http.get(AppConfig.VPP_REST_URL + AppConfig.API_V1_VPP + 'interfaces/tap', {params}).pipe(
      map(res => {
        return this.coreService.extractObjectDataToArray(res, VppInterfaceTapModel);
      })
    );
  }

  public getTapInterfacesRaw(vswitchIp: string) {
    const params = new HttpParams().set('vswitch', vswitchIp);
    return this.http.get(AppConfig.VPP_REST_URL + AppConfig.API_V1_VPP + 'interfaces/tap', {params});
  }

  public getBridgeDomains(vswitchIp: string): Observable<VppBdModel[]> {
    const params = new HttpParams().set('vswitch', vswitchIp);
    return this.http.get(AppConfig.VPP_REST_URL + AppConfig.API_V1_VPP + 'bd', {params}).pipe(
      map(res => {
        return this.coreService.extractObjectDataToArray(res, VppBdModel);
      })
    );
  }

  public getbridgeDomainsRaw(vswitchIp: string) {
    const params = new HttpParams().set('vswitch', vswitchIp);
    return this.http.get(AppConfig.VPP_REST_URL + AppConfig.API_V1_VPP + 'bd', {params});
  }

  public getNatRaw(vswitchIp: string) {
    const params = new HttpParams().set('vswitch', vswitchIp);
    return this.http.get(AppConfig.VPP_REST_URL + AppConfig.API_V1_VPP + 'nat', {params});
  }

  public getVersion(vswitchIp: string) {
    const params = new HttpParams().set('vswitch', vswitchIp);
    const headers = new HttpHeaders({
      'Content-Type':  'application/json',
    });

    const body = {'vppclicommand': 'show version'};

    return this.http.post(AppConfig.VPP_REST_URL + 'vpp/command', body, {params, headers, responseType: 'text'}).pipe(

    );
  }
}
