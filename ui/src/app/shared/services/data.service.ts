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
          return this.k8sService.loadNamespaces().pipe(
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
          return this.vppService.getBridgeDomains(d.node.ip).pipe(
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

  private getArpByIp(vswitchIp: string, ip: string): Observable<VppArpModel> {
    return this.vppService.getArps(vswitchIp).pipe(
      map(res => res.find(e => e.IP === ip))
    );
  }

  private getTapInterfaceByName(vswitchIp: string, ifName: string): Observable<VppInterfaceTapModel> {
    return this.vppService.getTapInterfaces(vswitchIp).pipe(
      map(res => res.find(e => e.name === ifName))
    );
  }

  private getInterfaceByPod(pod: K8sPodModel, vswitchIp: string): Observable<VppInterfaceTapModel> {
    return this.getArpByIp(vswitchIp, pod.podIp).pipe(
      switchMap(arp => {
        return arp ? this.getTapInterfaceByName(vswitchIp, arp.interface) : of(null);
      })
    );
  }

  private getInterfacesByPods(pods: K8sPodModel[], vswitchIp: string): Observable<VppInterfaceTapModel[]> {
    if (!pods.length) {
      return of(null);
    }

    const observables = pods.map(p => this.getInterfaceByPod(p, vswitchIp));

    return forkJoin(observables);
  }

  private getVrfInterfaces() {
    return this.getPodsVppIps().pipe(
      switchMap(data => {
        const observables = data.map(d => {
          return this.vppService.getInterfaces(d.node.ip).pipe(
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
          return this.getInterfacesByPods(d.vppPods, d.node.ip).pipe(
            map(res => {
              if (res) {
                res.forEach((r, i) => {
                  if (r) {
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
          return this.k8sService.loadPods().pipe(
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
    return this.k8sService.loadNodes().pipe(
      switchMap(nodes => {
        const observables = nodes.map(n => {
          return this.vppService.getIPAM(n.ip).pipe(
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

}
