import { NodeDataModel } from '../../d3-topology/topology/topology-data/models/node-data-model';
import { NodeType } from '../../d3-topology/topology/topology-data/interfaces/node-type';
import { TopologyType } from './topology-type';

export interface SpNodeItem {
  node: NodeDataModel;
  nodeType: NodeType;
  topology: TopologyType;
  bd?: string;
}
