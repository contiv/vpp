import { Injectable } from '@angular/core';
import { map, switchMap } from 'rxjs/operators';
import { Observable, forkJoin, of, BehaviorSubject, Subject } from 'rxjs';
import { KubernetesService } from './kubernetes.service';
import { VppService } from './vpp.service';
import { ContivDataModel } from '../models/contiv-data-model';
import { VppArpModel } from '../models/vpp/vpp-arp-model';
import { VppInterfaceTapModel } from '../models/vpp/vpp-interface-tap-model';
import { K8sPodModel } from '../models/k8s/k8s-pod-model';
import { AppConfig } from 'src/app/app-config';
import { K8sNodeModel } from '../models/k8s/k8s-node-model';
import { VppIpamModel } from '../models/vpp/vpp-ipam-model';

@Injectable({
  providedIn: 'root'
})
export class DataService {

  public contivData: ContivDataModel;
  public isDataLoading: Subject<boolean> = new Subject<boolean>();
  public isContivDataLoaded: BehaviorSubject<boolean> = new BehaviorSubject(false);

  constructor(
    private k8sService: KubernetesService,
    private vppService: VppService
  ) {
    this.loadData(true);
  }

  public loadData(first?: Boolean) {
    this.isDataLoading.next(true);

    if (!first) {
      this.isContivDataLoaded.next(false);
    }

    this.contivData = new ContivDataModel();

    this.getPodsNamespaces().subscribe(res => {
      res.forEach(r => this.contivData.addData(r));
      console.log(this.contivData);
      this.isContivDataLoaded.next(true);
      this.isDataLoading.next(false);
    });
  }

  public getPodsNamespaces() {
    return this.getNetworkData().pipe(
      switchMap(data => {
        const observables = data.map(d => {
          return this.k8sService.loadNamespaces(AppConfig.K8S_REST_MASTER_URL).pipe(
            map(res => {
              const namespaces = {
                namespaces: res
              };

              return Object.assign(d, namespaces);
            })
          );
        });

        return forkJoin(observables);
      })
    );
  }

  public getNetworkData() {
    return this.getBdByNode();
  }

  private getBdByNode() {
    return this.getVrfInterfaces().pipe(
      switchMap(data => {
        const observables = data.map(d => {
          const url = this.getRestUrl(d.node.name);
          return this.vppService.getBridgeDomains(url).pipe(
            map(res => {
              const bdObj = {
                bd: res
              };

              return Object.assign(d, bdObj);
            })
          );
        });

        return forkJoin(observables);
      })
    );
  }

  private getArpByIp(restUrl: string, ip: string): Observable<VppArpModel> {
    return this.vppService.getArps(restUrl).pipe(
      map(res => res.find(e => e.IP === ip))
    );
  }

  private getTapInterfaceByName(restUrl: string, ifName: string): Observable<VppInterfaceTapModel> {
    return this.vppService.getTapInterfaces(restUrl).pipe(
      map(res => res.find(e => e.name === ifName))
    );
  }

  private getInterfaceByPod(pod: K8sPodModel): Observable<VppInterfaceTapModel> {
    const url = this.getRestUrl(pod.node);

    return this.getArpByIp(url, pod.podIp).pipe(
      switchMap(arp => {
        return arp ? this.getTapInterfaceByName(url, arp.interface) : of(null);
      })
    );
  }

  private getInterfacesByPods(pods: K8sPodModel[]): Observable<VppInterfaceTapModel[]> {
    if (!pods.length) {
      return of(null);
    }

    const observables = pods.map(p => this.getInterfaceByPod(p));

    return forkJoin(observables);
  }

  private getVrfInterfaces() {
    return this.getPodsVppIps().pipe(
      switchMap(data => {
        const observables = data.map(d => {
          const url = this.getRestUrl(d.node.name);

          return this.vppService.getInterfaces(url).pipe(
            map(res => {
              const ifacesObject = {
                interfaces: res
              };

              return Object.assign(d, ifacesObject);
            })
          );
        });

        return forkJoin(observables);
      })
    );
  }

  private getPodsVppIps() {
    return this.getPodsByNode().pipe(
      switchMap(data => {
        const observables = data.map(d => {
          return this.getInterfacesByPods(d.vppPods).pipe(
            map(res => {
              if (res) {
                res.forEach((r, i) => {
                  if (r) {
                    d.vppPods[i].vppIp = r.IPS;
                    d.vppPods[i].tapInterface = r.name;
                    d.vppPods[i].tapInternalInterface = r.internalName;
                  }
                });
              }
              return d;
            })
          );
        });

        return forkJoin(observables);
      })
    );
  }

  private getPodsByNode() {
    return this.getIPAMbyNode().pipe(
      switchMap(data => {
        const observables = data.map(d => {
          /* TODO Move outside map */
          return this.k8sService.loadPods(AppConfig.K8S_REST_MASTER_URL).pipe(
            map(res => {
              const podsObj = {
                vppPods: res.filter(pod => pod.node === d.node.name && pod.hostIp !== pod.podIp),
                pods: res.filter(pod => pod.node === d.node.name && pod.hostIp === pod.podIp && !pod.name.includes('vswitch')),
                vswitch: res.find(pod => pod.node === d.node.name && pod.name.includes('vswitch'))
              };

              return Object.assign(d, podsObj);
            })
          );
        });

        return forkJoin(observables);
      })
    );
  }

  private getIPAMbyNode(): Observable<{
    node: K8sNodeModel;
    ipam: VppIpamModel;
  }[]> {
    return this.k8sService.loadNodes(AppConfig.K8S_REST_MASTER_URL).pipe(
      switchMap(nodes => {
        const observables = nodes.map(n => {
          const url = this.getRestUrl(n.name);

          return this.vppService.getIPAM(url).pipe(
            map(ipam => {
              return {
                node: n,
                ipam: ipam
              };
            })
          );
        });
        return forkJoin(observables);
      })
    );
  }

  public getRestUrl(nodeId: string): string {
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
}
