import { NodeDataModel } from '../../../topology/topology-data/models/node-data-model';

export interface NodeClickEvent {
  node: NodeDataModel;
  svgNode: any;
}
