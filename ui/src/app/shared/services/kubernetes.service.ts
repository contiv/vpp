import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { map, switchMap } from 'rxjs/operators';
import { AppConfig } from '../../app-config';
import { CoreService } from './core.service';
import { K8sPodModel } from '../models/k8s/k8s-pod-model';
import { K8sNodeModel } from '../models/k8s/k8s-node-model';
import { K8sServiceModel } from '../models/k8s/k8s-service-model';
import { K8sPolicyModel } from '../models/k8s/k8s-policy-model';
import { K8sNamespaceModel } from '../models/k8s/k8s-namespace-model';
import { K8sEndpointModel } from '../models/k8s/k8s-endpoint-model';

@Injectable({
  providedIn: 'root'
})
export class KubernetesService {

  constructor(
    private http: HttpClient,
    private coreService: CoreService
  ) { }

  public loadPods(restUrl: string): Observable<K8sPodModel[]> {
    return this.http.get(restUrl + AppConfig.API_V1 + 'pods').pipe(
      map(res => this.coreService.extractListData(res['items'] as Array<any>, K8sPodModel))
    );
  }

  public loadNodes(restUrl: string): Observable<K8sNodeModel[]> {
    return this.http.get(restUrl + AppConfig.API_V1 + 'nodes').pipe(
      map(res => this.coreService.extractListData(res['items'] as Array<any>, K8sNodeModel))
    );
  }

  public loadPolicies(restUrl: string): Observable<K8sPolicyModel[]> {
    return this.http.get(restUrl + AppConfig.API_V1_NETWORKING + 'networkpolicies').pipe(
      map(res => this.coreService.extractListData(res['items'] as Array<any>, K8sPolicyModel))
    );
  }

  public loadServices(restUrl: string): Observable<K8sServiceModel[]> {
    return this.http.get(restUrl + AppConfig.API_V1 + 'services').pipe(
      map(res => this.coreService.extractListData(res['items'] as Array<any>, K8sServiceModel))
    );
  }

  public loadEndpoints(restUrl: string): Observable<K8sEndpointModel[]> {
    return this.http.get(restUrl + AppConfig.API_V1 + 'endpoints').pipe(
      map(res => this.coreService.extractListData(res['items'] as Array<any>, K8sEndpointModel))
    );
  }

  public loadNamespaces(restUrl: string): Observable<K8sNamespaceModel[]> {
    return this.http.get(restUrl + AppConfig.API_V1 + 'namespaces').pipe(
      map(res => this.coreService.extractListData(res['items'] as Array<any>, K8sNamespaceModel))
    );
  }

}
