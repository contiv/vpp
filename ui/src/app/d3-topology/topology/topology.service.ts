import { Injectable } from '@angular/core';

import { Observable, Subject } from 'rxjs';
import { TopologyDataModel } from './topology-data/models/topology-data-model';
import { NodeDataModel } from './topology-data/models/node-data-model';
import { EdgeDataModel } from './topology-data/models/edge-data-model';
import { SvgTransform } from './interfaces/svg-transform';

@Injectable({
  providedIn: 'root'
})
export class TopologyService {

  private topologyDataSubject: Subject<TopologyDataModel> = new Subject<TopologyDataModel>();
  private topologyTransformSubject: Subject<SvgTransform> = new Subject<SvgTransform>();
  private topologyData: TopologyDataModel = new TopologyDataModel();
  private topologyTransform: SvgTransform;

  constructor() { }

  public setTopologyData(topologyData: TopologyDataModel) {
    this.topologyData = topologyData;
    this.updateTopology();
  }

  public setTopologyTransform(transform: SvgTransform) {
    this.topologyTransform = transform;
    this.topologyTransformSubject.next(transform);
  }

  public getTopologyTransform(): SvgTransform {
    return this.topologyTransform;
  }

  public getTopologyTransformSubject(): Subject<SvgTransform> {
    return this.topologyTransformSubject;
  }

  /**
   * Append new nodes into topologyData.nodes array
   */
  public appendNodes(nodes: NodeDataModel[]): void {
    this.topologyData.nodes = this.topologyData.nodes.concat(nodes);
  }

  /**
   * Append new links into topologyData.links array
   */
  public appendLinks(links: EdgeDataModel[]): void {
    this.topologyData.links = this.topologyData.links.concat(links);
  }

  /**
   * Get topologyData observable. Use, when you need to listen on data changes.
   */
  public getTopologyDataObservable(): Observable<TopologyDataModel> {
    return this.topologyDataSubject.asObservable();
  }

  /**
   * Get topologyData object. Use when you need actual data.
   */
  public getTopologyData(): TopologyDataModel {
    return this.topologyData;
  }

  /**
   * Find node in nodesArray and remove it
   */
  public findAndRemoveNodeFromTopology(node: NodeDataModel, removeLinks: boolean = true) {
    this.topologyData.removeNodeByNode(node);

    if (removeLinks) {
      this.findAndRemoveLinksByNodeId(node.id);
    }
  }


  /**
   * Find links attached to particular node and remove them from topology
   */
  public findAndRemoveLinksByNodeId(nodeId: string) {
    this.topologyData.removeLinksByNodeId(nodeId);
    this.updateTopology();
  }

  /**
   * Find link in linkArray and remove it
   */
  public findAndRemoveLinkFromTopology(link: EdgeDataModel) {
    this.topologyData.removeLinkByLink(link);
    this.updateTopology();
  }

  /**
   * Reset topologyData and clean topology of all nodes, links and buses
   */
  public clearTopology() {
    this.topologyData = new TopologyDataModel();
    this.updateTopology();
  }

  /**
   * Update node property values
   */
  public updateNode(originalNodeId: string, node: NodeDataModel): void {
    // find index of edited node
    const originalNode: NodeDataModel = this.topologyData.getNodeById(originalNodeId);

    if (originalNode != null) {
      // set new data to found node
      originalNode.setData(node);

      // fire topologyData change, on which renderTopology method is listening
      this.updateTopology();
    }
  }

  public updateTopology() {
    this.topologyDataSubject.next(this.topologyData);
  }

}
