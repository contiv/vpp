import { Injectable } from '@angular/core';
import { Subject } from 'rxjs';
import { NodeDataModel } from '../../d3-topology/topology/topology-data/models/node-data-model';
import { SpNodeItem } from '../interfaces/sp-node-item';
import { SpLinkItem } from '../interfaces/sp-link-item';
import { EdgeDataModel } from '../../d3-topology/topology/topology-data/models/edge-data-model';
import { TopologyType } from '../interfaces/topology-type';

@Injectable({
  providedIn: 'root'
})
export class SidepanelService {

  private selectedNodeSubject: Subject<SpNodeItem> = new Subject<SpNodeItem>();
  private selectedLinkSubject: Subject<SpLinkItem> = new Subject<SpLinkItem>();
  private sidepanelOpenedSubject: Subject<boolean> = new Subject<boolean>();

  constructor() { }

  public setSpNodeItem(item: NodeDataModel, topology: TopologyType) {
    const spItem: SpNodeItem = {
      node: item,
      nodeType: item ? item.nodeType : null,
      topology: topology
    };
    this.selectedNodeSubject.next(spItem);
  }

  public getSpNodeItem(): Subject<SpNodeItem> {
    return this.selectedNodeSubject;
  }

  public setSpLinkItem(item: EdgeDataModel, linkType: 'vppLink' | 'vxtunnel', topology: TopologyType) {
    const spItem: SpLinkItem = {
      link: item,
      linkType: linkType,
      topology: topology
    };
    this.selectedLinkSubject.next(spItem);
  }

  public getSpLinkItem(): Subject<SpLinkItem> {
    return this.selectedLinkSubject;
  }

  public openSidepanel() {
    this.sidepanelOpenedSubject.next(true);
  }

  public closeSidepanel() {
    this.sidepanelOpenedSubject.next(false);
  }

  public getSidepanelState(): Subject<boolean> {
    return this.sidepanelOpenedSubject;
  }
}
